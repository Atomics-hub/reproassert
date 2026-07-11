from __future__ import annotations

import base64
import binascii
import json
import math
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reproassert.dependency_attestor import (
    DEPENDENCY_TREE_ATTESTOR_SCRIPT,
    parse_container_tree_attestation,
)
from reproassert.errors import ReproAssertError
from reproassert.safeio import sanitize_log
from reproassert.source_attestation import (
    SOURCE_TREE_ALGORITHM,
    SOURCE_TREE_SPECIAL_ALGORITHM,
    ExpectedGitSpecialEntry,
    SourceAttestationLimits,
    SourceTreeAttestation,
    validate_expected_git_special_entries,
)

if TYPE_CHECKING:
    from reproassert.dependency_executor import DependencyVolumeHandle

DEFAULT_IMAGE = "reproassert-sandbox:0.1.0"
RUN_LABEL = "io.reproassert.run"
OWNER_LABEL_KEY = "io.reproassert.owner"
OWNER_LABEL_VALUE = "controller-v1"
OWNER_LABEL = f"{OWNER_LABEL_KEY}={OWNER_LABEL_VALUE}"
ONE_GIB = 1024 * 1024 * 1024
_IMAGE_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,199}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_DOCKER_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PYTEST_TARGET = re.compile(
    r"tests/reproassert/test_issue_([1-9][0-9]*)\.py::test_issue_([1-9][0-9]*)_reproduction"
)
_DEPENDENCY_LABEL_KEYS = {
    OWNER_LABEL_KEY,
    "io.reproassert.run",
    "io.reproassert.role",
    "io.reproassert.plan-sha256",
}
_MAX_TIMEOUT_SECONDS = 60 * 60
_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
_MIN_MEMORY_BYTES = 64 * 1024 * 1024
_MAX_MEMORY_BYTES = 16 * ONE_GIB
_MAX_CPUS = 64.0
_MAX_PIDS = 4_096
_MAX_DEPENDENCY_VOLUME_BYTES = 512 * 1024 * 1024
_RESULT_VOLUME_BYTES = 2 * 1024 * 1024
_RESULT_VOLUME_INODES = 64
_MIN_TMPFS_BYTES = 1024 * 1024
_MAX_TMPFS_BYTES = ONE_GIB
_MAX_TMPFS_INODES = 1_048_576
_MAX_JUNIT_BYTES = 1024 * 1024
_MAX_JUNIT_BASE64_BYTES = 4 * ((_MAX_JUNIT_BYTES + 2) // 3) + 1
_JUNIT_READER_SCRIPT = r"""
import base64
import os
import stat
import sys

path = "/results/junit.xml"
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    initial = os.fstat(descriptor)
    snapshot = (
        initial.st_dev,
        initial.st_ino,
        initial.st_mode,
        initial.st_size,
        initial.st_mtime_ns,
        initial.st_ctime_ns,
        initial.st_nlink,
    )
    if (
        not stat.S_ISREG(initial.st_mode)
        or initial.st_nlink != 1
        or initial.st_size < 1
        or initial.st_size > 1048576
    ):
        raise SystemExit(21)
    content = bytearray()
    while chunk := os.read(descriptor, 65536):
        content.extend(chunk)
        if len(content) > 1048576:
            raise SystemExit(22)
    final = os.fstat(descriptor)
    final_snapshot = (
        final.st_dev,
        final.st_ino,
        final.st_mode,
        final.st_size,
        final.st_mtime_ns,
        final.st_ctime_ns,
        final.st_nlink,
    )
    if final_snapshot != snapshot or len(content) != initial.st_size:
        raise SystemExit(23)
    sys.stdout.write(base64.b64encode(bytes(content)).decode("ascii") + "\n")
finally:
    os.close(descriptor)
""".strip()


@dataclass(frozen=True)
class SandboxPolicy:
    image: str = DEFAULT_IMAGE
    timeout_seconds: float = 60.0
    max_output_bytes: int = 64 * 1024
    memory_bytes: int = ONE_GIB
    cpus: float = 1.0
    pids: int = 128
    tmpfs_bytes: int = 64 * 1024 * 1024
    tmpfs_inodes: int = 4_096

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or _IMAGE_REFERENCE.fullmatch(self.image) is None:
            raise ValueError("image must be a bounded Docker image reference")
        _bounded_number(
            self.timeout_seconds,
            "timeout_seconds",
            minimum=0,
            maximum=_MAX_TIMEOUT_SECONDS,
        )
        _bounded_integer(
            self.max_output_bytes,
            "max_output_bytes",
            minimum=0,
            maximum=_MAX_OUTPUT_BYTES,
        )
        _bounded_integer(
            self.memory_bytes,
            "memory_bytes",
            minimum=_MIN_MEMORY_BYTES,
            maximum=_MAX_MEMORY_BYTES,
        )
        _bounded_number(self.cpus, "cpus", minimum=0.1, maximum=_MAX_CPUS)
        _bounded_integer(self.pids, "pids", minimum=1, maximum=_MAX_PIDS)
        _bounded_integer(
            self.tmpfs_bytes,
            "tmpfs_bytes",
            minimum=_MIN_TMPFS_BYTES,
            maximum=_MAX_TMPFS_BYTES,
        )
        _bounded_integer(
            self.tmpfs_inodes,
            "tmpfs_inodes",
            minimum=1,
            maximum=_MAX_TMPFS_INODES,
        )


@dataclass(frozen=True)
class DockerRunResult:
    phase: str
    exit_code: int | None
    duration_seconds: float
    output: str
    timed_out: bool
    oom_killed: bool
    output_truncated: bool
    junit_xml: bytes | None
    container_name: str
    argv: tuple[str, ...] = ()


@dataclass(frozen=True)
class DockerDoctor:
    cli_available: bool
    engine_available: bool
    image_available: bool
    server_version: str | None
    image_id: str | None


@dataclass(frozen=True)
class _BoundedCommandResult:
    returncode: int
    output: bytes
    timed_out: bool
    output_truncated: bool


class DockerSandbox:
    """Strict Docker boundary. It intentionally has no native execution fallback."""

    def __init__(self, policy: SandboxPolicy | None = None) -> None:
        self.policy = policy or SandboxPolicy()
        self._docker = shutil.which("docker")
        self._containers: set[str] = set()
        self._volumes: set[str] = set()
        self._result_anchors: dict[str, str] = {}
        self._resolved_image_id: str | None = None
        self._borrowed_dependency_volumes: dict[str, tuple[DependencyVolumeHandle, object]] = {}

    def doctor(self) -> DockerDoctor:
        if not self._docker:
            return DockerDoctor(False, False, False, None, None)
        info = self._control(["info", "--format", "{{json .}}"], check=False, timeout_seconds=15)
        if info.returncode != 0:
            return DockerDoctor(True, False, False, None, None)
        try:
            server_version = str(json.loads(info.stdout).get("ServerVersion") or "") or None
        except json.JSONDecodeError:
            server_version = None
        image = self._control(
            ["image", "inspect", self.policy.image, "--format", "{{.Id}}"],
            check=False,
            timeout_seconds=15,
        )
        return DockerDoctor(
            True,
            True,
            image.returncode == 0,
            server_version,
            image.stdout.strip() if image.returncode == 0 else None,
        )

    def require_ready(self) -> DockerDoctor:
        status = self.doctor()
        if not status.cli_available:
            raise ReproAssertError("sandbox_unavailable", "Docker CLI is required.")
        if not status.engine_available:
            raise ReproAssertError("sandbox_unavailable", "Docker engine is not running.")
        if not status.image_available:
            raise ReproAssertError(
                "sandbox_image_missing",
                f"Sandbox image is missing. Run: reproassert sandbox build ({self.policy.image}).",
            )
        if status.image_id is None or _IMAGE_ID.fullmatch(status.image_id) is None:
            raise ReproAssertError(
                "sandbox_image_invalid", "Docker returned an invalid immutable image ID."
            )
        if self._resolved_image_id is None:
            self._resolved_image_id = status.image_id
        elif self._resolved_image_id != status.image_id:
            raise ReproAssertError(
                "sandbox_image_changed", "Sandbox image tag changed during the controller run."
            )
        return status

    def build_image(self) -> str:
        if not self._docker:
            raise ReproAssertError("sandbox_unavailable", "Docker CLI is required.")
        with tempfile.TemporaryDirectory(prefix="reproassert-image-") as temporary:
            context = Path(temporary)
            assets = resources.files("reproassert").joinpath("assets")
            for name in ("Dockerfile", "requirements.lock"):
                destination = context / name
                with assets.joinpath(name).open("rb") as source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target)
            self._control(
                [
                    "build",
                    "--pull",
                    "--progress=plain",
                    "--tag",
                    self.policy.image,
                    str(context),
                ],
                timeout_seconds=600,
            )
        image = self._control(
            ["image", "inspect", self.policy.image, "--format", "{{.Id}}"],
            timeout_seconds=15,
        )
        image_id = image.stdout.strip()
        if _IMAGE_ID.fullmatch(image_id) is None:
            raise ReproAssertError(
                "sandbox_image_invalid", "Docker returned an invalid built image ID."
            )
        self._resolved_image_id = image_id
        return image_id

    def runner_facts(self) -> dict[str, str]:
        """Probe the trusted image without mounting or executing repository content."""

        self.require_ready()
        name = f"reproassert-facts-{uuid.uuid4().hex[:12]}"
        script = (
            "import json, platform, pytest; "
            "print(json.dumps({"
            "'python_version': platform.python_version(), "
            "'python_implementation': platform.python_implementation(), "
            "'pytest_version': pytest.__version__, "
            "'platform_system': platform.system(), "
            "'platform_release': platform.release(), "
            "'machine': platform.machine()"
            "}, sort_keys=True))"
        )
        self._containers.add(name)
        try:
            result = self._control(
                [
                    "run",
                    "--rm",
                    "--name",
                    name,
                    "--label",
                    OWNER_LABEL,
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
                    "32",
                    "--memory",
                    "268435456",
                    "--entrypoint",
                    "/usr/local/bin/python",
                    self._image_reference(),
                    "-c",
                    script,
                ],
                timeout_seconds=30,
            )
        finally:
            self._remove_container(name)
        try:
            values = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ReproAssertError(
                "sandbox_facts", "Runner image returned invalid environment facts."
            ) from exc
        required = {
            "python_version",
            "python_implementation",
            "pytest_version",
            "platform_system",
            "platform_release",
            "machine",
        }
        if (
            not isinstance(values, dict)
            or set(values) != required
            or not all(
                isinstance(values[key], str) and 0 < len(values[key]) <= 200 for key in required
            )
        ):
            raise ReproAssertError(
                "sandbox_facts", "Runner image returned incomplete environment facts."
            )
        return {key: sanitize_log(values[key], max_chars=200) for key in sorted(required)}

    def stage_source(self, source: Path, *, run_id: str) -> str:
        self.require_ready()
        source = source.resolve(strict=True)
        if not source.is_dir():
            raise ReproAssertError("source_directory", "Source workspace is not a directory.")
        token = _safe_token(run_id)
        volume = f"reproassert-{token}-{uuid.uuid4().hex[:10]}"
        stage = f"reproassert-stage-{token}-{uuid.uuid4().hex[:10]}"
        self._control(
            [
                "volume",
                "create",
                "--label",
                f"{RUN_LABEL}={run_id}",
                "--label",
                OWNER_LABEL,
                volume,
            ]
        )
        self._volumes.add(volume)
        try:
            try:
                self._control(
                    [
                        "create",
                        "--name",
                        stage,
                        "--label",
                        f"{RUN_LABEL}={run_id}",
                        "--label",
                        OWNER_LABEL,
                        "--pull",
                        "never",
                        "--no-healthcheck",
                        "--network",
                        "none",
                        "--mount",
                        f"type=volume,src={volume},dst=/workspace",
                        "--entrypoint",
                        "/bin/true",
                        self._image_reference(),
                    ]
                )
                self._containers.add(stage)
                self._control(["cp", "-a", f"{source}/.", f"{stage}:/workspace/"])
            finally:
                self._remove_container(stage)
            self._set_workspace_owner(volume, run_id=run_id)
            return volume
        except BaseException as exc:
            try:
                self._remove_volume(volume)
            except BaseException as cleanup_error:
                raise cleanup_error from exc
            raise

    def stage_attested_source(
        self,
        source: Path,
        *,
        run_id: str,
        expected: SourceTreeAttestation,
        limits: SourceAttestationLimits | None = None,
        expected_special_entries: tuple[ExpectedGitSpecialEntry, ...] = (),
    ) -> str:
        """Stage inert source and prove the exact staged bytes before execution."""

        volume = self.stage_source(source, run_id=run_id)
        try:
            observed = self.attest_staged_source(
                volume,
                run_id=run_id,
                limits=limits,
                expected_special_entries=expected_special_entries,
            )
            normalized = replace(
                observed,
                expected_git_tree_oid=expected.expected_git_tree_oid,
            )
            if normalized != expected:
                raise ReproAssertError(
                    "sandbox_stage_attestation",
                    "Staged workspace differs from the controller-attested source tree.",
                )
            return volume
        except BaseException as exc:
            try:
                self._remove_volume(volume)
            except BaseException as cleanup_error:
                raise cleanup_error from exc
            raise

    def attest_staged_source(
        self,
        volume: str,
        *,
        run_id: str,
        limits: SourceAttestationLimits | None = None,
        expected_special_entries: tuple[ExpectedGitSpecialEntry, ...] = (),
    ) -> SourceTreeAttestation:
        """Attest one controller-owned source volume in the pinned read-only image."""

        if volume not in self._volumes:
            raise ReproAssertError("sandbox_volume", "Workspace volume is not controller-owned.")
        active_limits = limits or SourceAttestationLimits()
        special_entries = validate_expected_git_special_entries(
            expected_special_entries, limits=active_limits
        )
        special_profile = json.dumps(
            [asdict(entry) for entry in special_entries],
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        name = f"reproassert-attest-{_safe_token(run_id)}-{uuid.uuid4().hex[:10]}"
        process_args = (
            "/usr/local/bin/python",
            "-I",
            "-c",
            DEPENDENCY_TREE_ATTESTOR_SCRIPT,
            "/workspace",
            str(active_limits.max_members),
            str(active_limits.max_files),
            str(active_limits.max_directories),
            str(active_limits.max_file_bytes),
            str(active_limits.max_total_bytes),
            str(active_limits.max_path_bytes),
            str(active_limits.max_component_bytes),
            special_profile,
        )
        self._control(
            self.verification_create_args(
                name=name,
                volume=volume,
                run_id=run_id,
                process_args=process_args,
            )
        )
        self._containers.add(name)
        try:
            self._assert_container_policy(name, volume=volume)
            attached = self._start_attached(name)
            if attached.removed or attached.timed_out or attached.output_truncated:
                raise ReproAssertError(
                    "sandbox_stage_attestation",
                    "Staged workspace attestation did not complete under policy.",
                )
            state = self._container_state(name)
            if (
                state.get("ExitCode") != 0
                or state.get("OOMKilled") is not False
                or state.get("Status") != "exited"
                or state.get("Running") is not False
                or state.get("Dead") is not False
                or state.get("Error") != ""
            ):
                raise ReproAssertError(
                    "sandbox_stage_attestation",
                    "Staged workspace attestor rejected the source tree.",
                )
            return parse_container_tree_attestation(
                attached.output,
                limits=active_limits,
                expected_algorithm=(
                    SOURCE_TREE_SPECIAL_ALGORITHM if special_entries else SOURCE_TREE_ALGORITHM
                ),
            )
        finally:
            self._remove_container(name)

    def run_pytest(
        self,
        *,
        volume: str,
        dependency_volume: str | None = None,
        target: str,
        phase: str,
        run_id: str,
        collect_only: bool = False,
    ) -> DockerRunResult:
        if volume not in self._volumes:
            raise ReproAssertError("sandbox_volume", "Workspace volume is not controller-owned.")
        if dependency_volume is not None:
            if dependency_volume not in self._borrowed_dependency_volumes:
                raise ReproAssertError(
                    "sandbox_volume", "Dependency volume is not an active typed borrow."
                )
            self._revalidate_borrowed_dependency(dependency_volume)
        target_match = _PYTEST_TARGET.fullmatch(target)
        if target_match is None or target_match.group(1) != target_match.group(2):
            raise ReproAssertError("sandbox_target", "Pytest target is not controller-approved.")
        name = f"reproassert-run-{_safe_token(run_id)}-{uuid.uuid4().hex[:10]}"
        result_volume = self._create_result_volume(run_id=run_id)
        junit_path = "/results/junit.xml"
        pytest_args = [
            "/usr/local/bin/python",
            "-m",
            "pytest",
            "-c",
            "/dev/null",
            "--rootdir=/workspace",
            "-p",
            "no:cacheprovider",
            "--import-mode=importlib",
            "--color=no",
            "--tb=short",
            "--basetemp=/tmp/pytest",
            f"--junitxml={junit_path}",
        ]
        if collect_only:
            pytest_args.extend(["--collect-only", "-q"])
        else:
            pytest_args.extend(["-q"])
        pytest_args.append(target)
        create_args = self.verification_create_args(
            name=name,
            volume=volume,
            dependency_volume=dependency_volume,
            result_volume=result_volume,
            run_id=run_id,
            process_args=pytest_args,
        )
        try:
            self._control(create_args)
            self._containers.add(name)
            started = time.monotonic()
            try:
                self._assert_container_policy(
                    name,
                    volume=volume,
                    dependency_volume=dependency_volume,
                    result_volume=result_volume,
                )
                attached = self._start_attached(name)
                state = self._container_state(name) if not attached.removed else {}
                junit = None
                if not attached.removed and not attached.timed_out:
                    junit = self._copy_junit(result_volume, junit_path)
                return DockerRunResult(
                    phase=phase,
                    exit_code=_optional_int(state.get("ExitCode")),
                    duration_seconds=time.monotonic() - started,
                    output=attached.output,
                    timed_out=attached.timed_out,
                    oom_killed=bool(state.get("OOMKilled", False)),
                    output_truncated=attached.output_truncated,
                    junit_xml=junit,
                    container_name=name,
                    argv=tuple(pytest_args),
                )
            finally:
                self._remove_container(name)
        finally:
            self._remove_volume(result_volume)

    def verification_create_args(
        self,
        *,
        name: str,
        volume: str,
        dependency_volume: str | None = None,
        result_volume: str | None = None,
        run_id: str,
        process_args: Sequence[str],
    ) -> list[str]:
        p = self.policy
        python_path = "/workspace:/workspace/src:/workspace/.reproassert-deps"
        if dependency_volume is not None:
            python_path = "/workspace:/workspace/src:/dependencies:/workspace/.reproassert-deps"
        args = [
            "create",
            "--name",
            name,
            "--label",
            f"{RUN_LABEL}={run_id}",
            "--label",
            OWNER_LABEL,
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
            str(p.pids),
            "--memory",
            str(p.memory_bytes),
            "--memory-swap",
            str(p.memory_bytes),
            "--cpus",
            str(p.cpus),
            "--ulimit",
            "nofile=256:256",
            "--ulimit",
            "core=0:0",
            "--ulimit",
            "fsize=67108864:67108864",
            "--shm-size",
            "64m",
            "--init",
            "--tmpfs",
            (
                f"/tmp:rw,noexec,nosuid,nodev,size={p.tmpfs_bytes},nr_inodes={p.tmpfs_inodes}"  # noqa: S108 - container tmpfs target
            ),
            "--mount",
            f"type=volume,src={volume},dst=/workspace,readonly",
        ]
        if dependency_volume is not None:
            args.extend(
                [
                    "--mount",
                    f"type=volume,src={dependency_volume},dst=/dependencies,readonly",
                ]
            )
        if result_volume is not None:
            args.extend(
                [
                    "--mount",
                    f"type=volume,src={result_volume},dst=/results",
                ]
            )
        args.extend(
            [
                "--workdir",
                "/workspace",
                "--log-driver",
                "local",
                "--log-opt",
                "max-size=128k",
                "--log-opt",
                "max-file=1",
                "--log-opt",
                "compress=false",
                "--entrypoint",
                "/usr/bin/env",
                self._image_reference(),
                "-i",
                "HOME=/tmp/home",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE=1",
                "PYTHONHASHSEED=0",
                f"PYTHONPATH={python_path}",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
                "TZ=UTC",
                *process_args,
            ]
        )
        return args

    def cleanup(self) -> None:
        failures: list[str] = []
        for container in tuple(self._containers):
            try:
                self._remove_container(container)
            except ReproAssertError as exc:
                failures.append(f"container {container}: {exc.message}")
        for volume in tuple(self._volumes):
            try:
                self._remove_volume(volume)
            except ReproAssertError as exc:
                failures.append(f"volume {volume}: {exc.message}")
        if failures:
            raise ReproAssertError(
                "sandbox_cleanup",
                "Controller-owned Docker resource cleanup failed: " + "; ".join(sorted(failures)),
            )

    @contextmanager
    def borrow_dependency_volume(self, handle: DependencyVolumeHandle) -> Iterator[str]:
        """Borrow an executor-owned dependency volume without taking cleanup ownership."""

        from reproassert.dependency_executor import DependencyVolumeHandle

        if type(handle) is not DependencyVolumeHandle:
            raise ReproAssertError(
                "sandbox_dependency_handle", "Dependency handle type is not controller-owned."
            )
        self.require_ready()
        name = handle.name
        if (
            not isinstance(name, str)
            or _DOCKER_TOKEN.fullmatch(name) is None
            or name in self._volumes
            or name in self._borrowed_dependency_volumes
        ):
            raise ReproAssertError(
                "sandbox_dependency_handle", "Dependency volume name is unsafe or already owned."
            )
        validation = self._validate_dependency_handle(handle)
        self._borrowed_dependency_volumes[name] = (handle, validation)
        try:
            yield name
        finally:
            current = self._borrowed_dependency_volumes.get(name)
            if current is not None and current[0] is handle:
                self._borrowed_dependency_volumes.pop(name, None)

    def _revalidate_borrowed_dependency(self, name: str) -> None:
        try:
            handle, original = self._borrowed_dependency_volumes[name]
        except KeyError as exc:  # pragma: no cover - guarded by caller
            raise ReproAssertError(
                "sandbox_dependency_handle", "Dependency volume borrow is not active."
            ) from exc
        current = self._validate_dependency_handle(handle)
        if current != original:
            raise ReproAssertError(
                "sandbox_dependency_handle", "Dependency volume changed after it was borrowed."
            )

    def _validate_dependency_handle(self, handle: DependencyVolumeHandle) -> object:
        ownership = getattr(handle.cleanup_ownership, "value", None)
        if ownership != "dependency_executor_context":
            raise ReproAssertError(
                "sandbox_dependency_handle", "Dependency cleanup ownership is unsupported."
            )
        if self._resolved_image_id is None or handle.image_id != self._resolved_image_id:
            raise ReproAssertError(
                "sandbox_dependency_handle", "Dependency and verifier image IDs differ."
            )
        try:
            labels = dict(handle.labels)
        except (TypeError, ValueError) as exc:
            raise ReproAssertError(
                "sandbox_dependency_handle", "Dependency volume labels are invalid."
            ) from exc
        if (
            set(labels) != _DEPENDENCY_LABEL_KEYS
            or labels.get(OWNER_LABEL_KEY) != OWNER_LABEL_VALUE
            or labels.get("io.reproassert.role") != "dependencies"
            or _DOCKER_TOKEN.fullmatch(labels.get("io.reproassert.run", "")) is None
            or _SHA256.fullmatch(labels.get("io.reproassert.plan-sha256", "")) is None
        ):
            raise ReproAssertError(
                "sandbox_dependency_handle", "Dependency volume labels are invalid."
            )
        validation = handle.revalidate_for_mount()
        if (
            getattr(validation, "name", None) != handle.name
            or getattr(validation, "labels", None) != handle.labels
            or getattr(validation, "image_id", None) != handle.image_id
            or getattr(validation, "quota", None) != getattr(handle, "quota", None)
            or getattr(validation, "volume_probe", None) != getattr(handle, "volume_probe", None)
            or getattr(validation, "tree_attestation", None)
            != getattr(handle, "tree_attestation", None)
            or getattr(validation, "execution_receipt_sha256", None)
            != getattr(handle, "execution_receipt_sha256", None)
        ):
            raise ReproAssertError(
                "sandbox_dependency_handle", "Dependency handle revalidation is inconsistent."
            )
        quota = getattr(validation, "quota", None)
        tree = getattr(validation, "tree_attestation", None)
        receipt_sha256 = getattr(validation, "execution_receipt_sha256", None)
        quota_size = getattr(quota, "size_bytes", None)
        quota_inodes = getattr(quota, "max_inodes", None)
        if (
            getattr(quota, "driver", None) != "local"
            or getattr(quota, "scope", None) != "local"
            or getattr(quota, "type", None) != "tmpfs"
            or getattr(quota, "device", None) != "tmpfs"
            or getattr(quota, "uid", None) != 65532
            or getattr(quota, "gid", None) != 65532
            or getattr(quota, "mode", None) != 0o700
            or not isinstance(quota_size, int)
            or quota_size != _MAX_DEPENDENCY_VOLUME_BYTES
            or not isinstance(quota_inodes, int)
            or quota_inodes != 32_768
            or not isinstance(receipt_sha256, str)
            or _SHA256.fullmatch(receipt_sha256) is None
            or getattr(tree, "algorithm", None) != "reproassert-source-tree-v1"
            or getattr(tree, "expected_git_tree_oid", None) is not None
            or getattr(tree, "git_metadata_absent", None) is not True
        ):
            raise ReproAssertError(
                "sandbox_dependency_handle", "Dependency quota or tree evidence is invalid."
            )
        return validation

    def _create_result_volume(self, *, run_id: str) -> str:
        """Create one bounded tmpfs used only for controller-requested JUnit transport."""

        name = f"reproassert-result-{_safe_token(run_id)}-{uuid.uuid4().hex[:10]}"
        labels = {
            OWNER_LABEL_KEY: OWNER_LABEL_VALUE,
            RUN_LABEL: run_id,
            "io.reproassert.role": "junit-result",
        }
        options = {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": (
                f"size={_RESULT_VOLUME_BYTES},nr_inodes={_RESULT_VOLUME_INODES},"
                "uid=65532,gid=65532,mode=0700"
            ),
        }
        args = ["volume", "create"]
        for key, value in sorted(labels.items()):
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
                f"o={options['o']}",
                name,
            ]
        )
        created = self._control(args, timeout_seconds=30)
        self._volumes.add(name)
        try:
            if created.stdout.strip() != name:
                raise ReproAssertError(
                    "sandbox_result_volume", "Docker created an unexpected result volume."
                )
            inspected = self._inspect_volume(name)
            if (
                inspected is None
                or inspected.get("Driver") != "local"
                or inspected.get("Scope") != "local"
                or inspected.get("Labels") != labels
                or inspected.get("Options") != options
            ):
                raise ReproAssertError(
                    "sandbox_result_volume",
                    "Docker did not apply the exact bounded result-volume policy.",
                )
            self._start_result_anchor(name, run_id=run_id)
            return name
        except BaseException as exc:
            try:
                self._remove_volume(name)
            except BaseException as cleanup_error:
                raise cleanup_error from exc
            raise

    def _start_result_anchor(self, volume: str, *, run_id: str) -> None:
        """Keep one local-driver tmpfs mount alive until JUnit has been copied."""

        name = f"reproassert-result-anchor-{_safe_token(run_id)}-{uuid.uuid4().hex[:10]}"
        process_args = ["-I", "-c", "import time; time.sleep(3600)"]
        args = [
            "create",
            "--name",
            name,
            "--label",
            f"{RUN_LABEL}={run_id}",
            "--label",
            OWNER_LABEL,
            "--label",
            "io.reproassert.role=junit-result-anchor",
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
            "16",
            "--memory",
            "67108864",
            "--memory-swap",
            "67108864",
            "--cpus",
            "0.1",
            "--shm-size",
            "1m",
            "--init",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=1048576,nr_inodes=64",  # noqa: S108
            "--mount",
            f"type=volume,src={volume},dst=/results",
            "--workdir",
            "/",
            "--log-driver",
            "none",
            "--entrypoint",
            "/usr/local/bin/python",
            self._image_reference(),
            *process_args,
        ]
        self._control(args, timeout_seconds=30)
        self._containers.add(name)
        self._result_anchors[volume] = name
        self._control(["start", name], timeout_seconds=30)
        self._assert_result_anchor_policy(
            name,
            volume=volume,
            process_args=process_args,
        )

    def _assert_result_anchor_policy(
        self,
        name: str,
        *,
        volume: str,
        process_args: list[str],
    ) -> None:
        inspected = self._inspect(name)
        host = inspected.get("HostConfig", {})
        config = inspected.get("Config", {})
        state = inspected.get("State", {})
        mounts = inspected.get("Mounts", [])
        checks = {
            "image": self._resolved_image_id is None
            or inspected.get("Image") == self._resolved_image_id,
            "network": host.get("NetworkMode") == "none",
            "root": host.get("ReadonlyRootfs") is True,
            "user": config.get("User") == "65532:65532",
            "caps": {str(value).upper() for value in host.get("CapDrop") or []} == {"ALL"},
            "security": "no-new-privileges=true" in set(host.get("SecurityOpt") or []),
            "privileged": host.get("Privileged") is False,
            "pid": not host.get("PidMode"),
            "ipc": host.get("IpcMode") == "private",
            "cgroup": host.get("CgroupnsMode") == "private",
            "pids": host.get("PidsLimit") == 16,
            "memory": host.get("Memory") == 67_108_864,
            "swap": host.get("MemorySwap") == 67_108_864,
            "cpus": host.get("NanoCpus") == 100_000_000,
            "health": config.get("Healthcheck") == {"Test": ["NONE"]},
            "entrypoint": config.get("Entrypoint") == ["/usr/local/bin/python"],
            "command": config.get("Cmd") == process_args,
            "mount": len(mounts) == 1
            and mounts[0].get("Type") == "volume"
            and mounts[0].get("Name") == volume
            and mounts[0].get("Destination") == "/results"
            and mounts[0].get("RW") is True,
            "running": state.get("Running") is True
            and state.get("Status") == "running"
            and state.get("OOMKilled") is False,
        }
        failed = sorted(key for key, accepted in checks.items() if not accepted)
        if failed:
            raise ReproAssertError(
                "sandbox_result_anchor",
                "Docker did not apply exact result-anchor policy: " + ", ".join(failed),
            )

    def _set_workspace_owner(self, volume: str, *, run_id: str) -> None:
        name = f"reproassert-owner-{_safe_token(run_id)}-{uuid.uuid4().hex[:10]}"
        args = [
            "create",
            "--name",
            name,
            "--label",
            f"{RUN_LABEL}={run_id}",
            "--label",
            OWNER_LABEL,
            "--pull",
            "never",
            "--no-healthcheck",
            "--network",
            "none",
            "--read-only",
            "--user",
            "0:0",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "DAC_READ_SEARCH",
            "--security-opt",
            "no-new-privileges=true",
            "--cgroupns",
            "private",
            "--ipc",
            "private",
            "--mount",
            f"type=volume,src={volume},dst=/workspace",
            "--entrypoint",
            "/bin/chown",
            self._image_reference(),
            "-R",
            "65532:65532",
            "/workspace",
        ]
        self._control(args)
        self._containers.add(name)
        try:
            self._control(["start", "-a", name], timeout_seconds=60)
            state = self._container_state(name)
            if state.get("ExitCode") != 0:
                raise ReproAssertError("sandbox_stage", "Could not set workspace ownership.")
        finally:
            self._remove_container(name)

    def _assert_container_policy(
        self,
        name: str,
        *,
        volume: str,
        dependency_volume: str | None = None,
        result_volume: str | None = None,
    ) -> None:
        inspected = self._inspect(name)
        host = inspected.get("HostConfig", {})
        config = inspected.get("Config", {})
        mounts = inspected.get("Mounts", [])
        security = set(host.get("SecurityOpt") or [])
        cap_drop = {str(value).upper() for value in host.get("CapDrop") or []}
        expected_nano_cpus = int(self.policy.cpus * 1_000_000_000)
        expected_volumes = {volume}
        if dependency_volume is not None:
            expected_volumes.add(dependency_volume)
        if result_volume is not None:
            expected_volumes.add(result_volume)
        checks = {
            "network_none": host.get("NetworkMode") == "none",
            "readonly_root": host.get("ReadonlyRootfs") is True,
            "non_root": config.get("User") == "65532:65532",
            "caps_dropped": "ALL" in cap_drop,
            "no_new_privileges": "no-new-privileges=true" in security,
            "not_privileged": host.get("Privileged") is False,
            "pid_private": not host.get("PidMode"),
            "ipc_private": host.get("IpcMode") == "private",
            "cgroup_private": host.get("CgroupnsMode") == "private",
            "healthcheck_disabled": config.get("Healthcheck") == {"Test": ["NONE"]},
            "pids": host.get("PidsLimit") == self.policy.pids,
            "memory": host.get("Memory") == self.policy.memory_bytes,
            "memory_swap": host.get("MemorySwap") == self.policy.memory_bytes,
            "cpus": host.get("NanoCpus") == expected_nano_cpus,
            "no_devices": not host.get("Devices"),
            "no_binds": not host.get("Binds"),
            "immutable_image": self._resolved_image_id is None
            or inspected.get("Image") == self._resolved_image_id,
            "workspace_ro": any(
                mount.get("Name") == volume
                and mount.get("Destination") == "/workspace"
                and mount.get("RW") is False
                for mount in mounts
            ),
            "dependencies_ro": dependency_volume is None
            or any(
                mount.get("Name") == dependency_volume
                and mount.get("Destination") == "/dependencies"
                and mount.get("RW") is False
                for mount in mounts
            ),
            "results_rw": result_volume is None
            or any(
                mount.get("Name") == result_volume
                and mount.get("Destination") == "/results"
                and mount.get("RW") is True
                for mount in mounts
            ),
            "only_expected_mounts": len(mounts) == len(expected_volumes)
            and all(
                mount.get("Type") == "volume" and mount.get("Name") in expected_volumes
                for mount in mounts
            ),
        }
        failed = sorted(key for key, passed in checks.items() if not passed)
        if failed:
            self._remove_container(name)
            raise ReproAssertError(
                "sandbox_policy_not_applied", f"Docker did not apply: {', '.join(failed)}"
            )

    def _start_attached(self, name: str) -> _AttachedResult:
        command = [self._docker_path(), "start", "-a", name]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = bytearray()
        overflow = threading.Event()

        def read_output() -> None:
            stream = process.stdout
            if stream is None:
                return
            while chunk := stream.read(8_192):
                remaining = self.policy.max_output_bytes - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()

        reader = threading.Thread(target=read_output, name="reproassert-docker-output", daemon=True)
        reader.start()
        started = time.monotonic()
        timed_out = False
        removed = False
        while process.poll() is None:
            if overflow.is_set() or time.monotonic() - started > self.policy.timeout_seconds:
                timed_out = not overflow.is_set()
                self._remove_container(name)
                removed = True
                process.kill()
                break
            time.sleep(0.05)
        process.wait(timeout=5)
        reader.join(timeout=2)
        return _AttachedResult(
            output=_sanitize_output(bytes(output)),
            output_truncated=overflow.is_set(),
            timed_out=timed_out,
            removed=removed,
        )

    def _copy_junit(self, result_volume: str, path: str) -> bytes | None:
        if path != "/results/junit.xml":
            return None
        anchor = self._result_anchors.get(result_volume)
        if anchor is None or anchor not in self._containers:
            return None
        result = self._run_bounded_docker_command(
            [
                "exec",
                anchor,
                "/usr/local/bin/python",
                "-I",
                "-c",
                _JUNIT_READER_SCRIPT,
            ],
            timeout_seconds=20,
            max_output_bytes=_MAX_JUNIT_BASE64_BYTES,
        )
        if result.returncode != 0 or result.timed_out or result.output_truncated:
            return None
        if not result.output.endswith(b"\n") or result.output.count(b"\n") != 1:
            return None
        try:
            encoded = result.output[:-1]
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            return None
        if not 1 <= len(content) <= _MAX_JUNIT_BYTES:
            return None
        return content

    def _run_bounded_docker_command(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> _BoundedCommandResult:
        command = [self._docker_path(), *args]
        process = subprocess.Popen(
            command,
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

        reader = threading.Thread(
            target=read_output,
            name="reproassert-junit-reader",
            daemon=True,
        )
        reader.start()
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
        return _BoundedCommandResult(
            returncode=process.returncode,
            output=bytes(output),
            timed_out=timed_out,
            output_truncated=overflow.is_set(),
        )

    def _container_state(self, name: str) -> dict[str, Any]:
        return dict(self._inspect(name).get("State", {}))

    def _inspect(self, name: str) -> dict[str, Any]:
        result = self._control(["inspect", name], timeout_seconds=20)
        try:
            values = json.loads(result.stdout)
            if len(values) != 1 or not isinstance(values[0], dict):
                raise ValueError
            return dict(values[0])
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ReproAssertError(
                "sandbox_inspect", "Docker inspect returned invalid data."
            ) from exc

    def _remove_container(self, name: str) -> None:
        if not self._docker:
            return
        inspected = self._inspect_container_optional(name)
        if inspected is None:
            self._containers.discard(name)
            self._forget_result_anchor_container(name)
            return
        config = inspected.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if not isinstance(labels, dict) or labels.get(OWNER_LABEL_KEY) != OWNER_LABEL_VALUE:
            raise ReproAssertError(
                "sandbox_cleanup", "Refusing to remove a container without the controller label."
            )
        removed = self._control(["container", "rm", "-f", name], check=False, timeout_seconds=20)
        if removed.returncode != 0:
            raise ReproAssertError("sandbox_cleanup", "Docker did not remove the owned container.")
        if self._inspect_container_optional(name) is not None:
            raise ReproAssertError(
                "sandbox_cleanup", "Docker still reports the owned container after removal."
            )
        self._containers.discard(name)
        self._forget_result_anchor_container(name)

    def _forget_result_anchor_container(self, name: str) -> None:
        for volume, anchor in tuple(self._result_anchors.items()):
            if anchor == name:
                self._result_anchors.pop(volume, None)

    def _inspect_container_optional(self, name: str) -> dict[str, Any] | None:
        result = self._control(["container", "inspect", name], check=False, timeout_seconds=20)
        if result.returncode != 0:
            if self._resource_name_exists("container", name):
                raise ReproAssertError(
                    "sandbox_cleanup", "Docker could not inspect an existing container."
                )
            return None
        try:
            values = json.loads(result.stdout)
            if (
                len(values) != 1
                or not isinstance(values[0], dict)
                or values[0].get("Name") != f"/{name}"
            ):
                raise ValueError
            return dict(values[0])
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ReproAssertError(
                "sandbox_cleanup", "Docker container inspect returned invalid data."
            ) from exc

    def _remove_volume(self, name: str) -> None:
        anchor = self._result_anchors.pop(name, None)
        if anchor is not None:
            self._remove_container(anchor)
        inspected = self._inspect_volume(name)
        if inspected is None:
            self._volumes.discard(name)
            return
        labels = inspected.get("Labels")
        if not isinstance(labels, dict) or labels.get(OWNER_LABEL_KEY) != OWNER_LABEL_VALUE:
            raise ReproAssertError(
                "sandbox_cleanup", "Refusing to remove a volume without the controller label."
            )
        removed = self._control(["volume", "rm", name], check=False, timeout_seconds=30)
        if removed.returncode != 0:
            raise ReproAssertError("sandbox_cleanup", "Docker did not remove the owned volume.")
        if self._inspect_volume(name) is not None:
            raise ReproAssertError(
                "sandbox_cleanup", "Docker still reports the owned volume after removal."
            )
        self._volumes.discard(name)

    def _inspect_volume(self, name: str) -> dict[str, Any] | None:
        result = self._control(["volume", "inspect", name], check=False, timeout_seconds=20)
        if result.returncode != 0:
            if self._resource_name_exists("volume", name):
                raise ReproAssertError(
                    "sandbox_cleanup", "Docker could not inspect an existing volume."
                )
            return None
        try:
            values = json.loads(result.stdout)
            if len(values) != 1 or not isinstance(values[0], dict) or values[0].get("Name") != name:
                raise ValueError
            return dict(values[0])
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ReproAssertError(
                "sandbox_cleanup", "Docker volume inspect returned invalid data."
            ) from exc

    def _resource_name_exists(self, kind: str, name: str) -> bool:
        if kind == "container":
            args = [
                "container",
                "ls",
                "--all",
                "--filter",
                f"name=^/{re.escape(name)}$",
                "--format",
                "{{.Names}}",
            ]
        elif kind == "volume":
            args = [
                "volume",
                "ls",
                "--filter",
                f"name=^{re.escape(name)}$",
                "--format",
                "{{.Name}}",
            ]
        else:  # pragma: no cover - controller-only invariant
            raise ValueError("unsupported Docker resource kind")
        listed = self._control(args, check=False, timeout_seconds=20)
        if listed.returncode != 0:
            raise ReproAssertError("sandbox_cleanup", f"Docker could not prove {kind} absence.")
        names = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
        if any(value != name for value in names) or len(names) > 1:
            raise ReproAssertError(
                "sandbox_cleanup", f"Docker returned ambiguous {kind} name evidence."
            )
        return names == [name]

    def _control(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
        timeout_seconds: float = 60,
    ) -> subprocess.CompletedProcess[str]:
        command = [self._docker_path(), *args]
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                env={
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                },
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ReproAssertError(
                "docker_timeout", f"Docker command timed out: {args[0]}"
            ) from exc
        if check and result.returncode != 0:
            message = _sanitize_output((result.stderr or result.stdout).encode("utf-8"))
            raise ReproAssertError(
                "docker_failed", f"Docker {args[0]} failed ({result.returncode}): {message[:500]}"
            )
        return result

    def _docker_path(self) -> str:
        if not self._docker:
            raise ReproAssertError("sandbox_unavailable", "Docker CLI is required.")
        return self._docker

    def _image_reference(self) -> str:
        return self._resolved_image_id or self.policy.image


@dataclass(frozen=True)
class _AttachedResult:
    output: str
    output_truncated: bool
    timed_out: bool
    removed: bool


def _bounded_integer(value: object, label: str, *, minimum: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}")


def _bounded_number(value: object, label: str, *, minimum: float, maximum: float) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise ValueError(f"{label} must be a finite number between {minimum} and {maximum}")


def _safe_token(value: str) -> str:
    token = "".join(character for character in value.lower() if character.isalnum())[:24]
    return token or uuid.uuid4().hex[:12]


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _sanitize_output(data: bytes) -> str:
    return sanitize_log(data.decode("utf-8", errors="replace"))
