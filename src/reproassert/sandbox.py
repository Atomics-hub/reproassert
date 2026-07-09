from __future__ import annotations

import json
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from reproassert.errors import ReproAssertError
from reproassert.safeio import sanitize_log

DEFAULT_IMAGE = "reproassert-sandbox:0.1.0"
RUN_LABEL = "io.reproassert.run"
OWNER_LABEL = "io.reproassert.owner=controller-v1"
ONE_GIB = 1024 * 1024 * 1024


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


class DockerSandbox:
    """Strict Docker boundary. It intentionally has no native execution fallback."""

    def __init__(self, policy: SandboxPolicy | None = None) -> None:
        self.policy = policy or SandboxPolicy()
        self._docker = shutil.which("docker")
        self._containers: set[str] = set()
        self._volumes: set[str] = set()

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
        return image.stdout.strip()

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
                    "268435456",
                    "--entrypoint",
                    "/usr/local/bin/python",
                    self.policy.image,
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
            self._control(
                [
                    "create",
                    "--name",
                    stage,
                    "--label",
                    f"{RUN_LABEL}={run_id}",
                    "--label",
                    OWNER_LABEL,
                    "--network",
                    "none",
                    "--mount",
                    f"type=volume,src={volume},dst=/workspace",
                    "--entrypoint",
                    "/bin/true",
                    self.policy.image,
                ]
            )
            self._containers.add(stage)
            self._control(["cp", "-a", f"{source}/.", f"{stage}:/workspace/"])
        finally:
            self._remove_container(stage)
        self._set_workspace_owner(volume, run_id=run_id)
        return volume

    def run_pytest(
        self,
        *,
        volume: str,
        target: str,
        phase: str,
        run_id: str,
        collect_only: bool = False,
    ) -> DockerRunResult:
        if volume not in self._volumes:
            raise ReproAssertError("sandbox_volume", "Workspace volume is not controller-owned.")
        if not target.startswith("tests/reproassert/") or target.startswith("-"):
            raise ReproAssertError("sandbox_target", "Pytest target is not controller-approved.")
        name = f"reproassert-run-{_safe_token(run_id)}-{uuid.uuid4().hex[:10]}"
        junit_path = f"/tmp/{uuid.uuid4().hex}.xml"  # noqa: S108 - path is inside container
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
            run_id=run_id,
            process_args=pytest_args,
        )
        self._control(create_args)
        self._containers.add(name)
        started = time.monotonic()
        try:
            self._assert_container_policy(name, volume=volume)
            attached = self._start_attached(name)
            state = self._container_state(name) if not attached.removed else {}
            junit = None
            if not attached.removed and not attached.timed_out:
                junit = self._copy_junit(name, junit_path)
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

    def verification_create_args(
        self,
        *,
        name: str,
        volume: str,
        run_id: str,
        process_args: Sequence[str],
    ) -> list[str]:
        p = self.policy
        return [
            "create",
            "--name",
            name,
            "--label",
            f"{RUN_LABEL}={run_id}",
            "--label",
            OWNER_LABEL,
            "--pull",
            "never",
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
            p.image,
            "-i",
            "HOME=/tmp/home",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONHASHSEED=0",
            "PYTHONPATH=/workspace:/workspace/src:/workspace/.reproassert-deps",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
            "TZ=UTC",
            *process_args,
        ]

    def cleanup(self) -> None:
        for container in tuple(self._containers):
            self._remove_container(container)
        for volume in tuple(self._volumes):
            self._control(["volume", "rm", "-f", volume], check=False, timeout_seconds=30)
            self._volumes.discard(volume)

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
            "--network",
            "none",
            "--read-only",
            "--user",
            "0:0",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--security-opt",
            "no-new-privileges=true",
            "--mount",
            f"type=volume,src={volume},dst=/workspace",
            "--entrypoint",
            "/bin/chown",
            self.policy.image,
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

    def _assert_container_policy(self, name: str, *, volume: str) -> None:
        inspected = self._inspect(name)
        host = inspected.get("HostConfig", {})
        config = inspected.get("Config", {})
        mounts = inspected.get("Mounts", [])
        security = set(host.get("SecurityOpt") or [])
        cap_drop = {str(value).upper() for value in host.get("CapDrop") or []}
        expected_nano_cpus = int(self.policy.cpus * 1_000_000_000)
        checks = {
            "network_none": host.get("NetworkMode") == "none",
            "readonly_root": host.get("ReadonlyRootfs") is True,
            "non_root": config.get("User") == "65532:65532",
            "caps_dropped": "ALL" in cap_drop,
            "no_new_privileges": "no-new-privileges=true" in security,
            "not_privileged": host.get("Privileged") is False,
            "pid_private": not host.get("PidMode"),
            "ipc_private": host.get("IpcMode") in ("private", ""),
            "pids": host.get("PidsLimit") == self.policy.pids,
            "memory": host.get("Memory") == self.policy.memory_bytes,
            "memory_swap": host.get("MemorySwap") == self.policy.memory_bytes,
            "cpus": host.get("NanoCpus") == expected_nano_cpus,
            "no_devices": not host.get("Devices"),
            "no_binds": not host.get("Binds"),
            "workspace_ro": any(
                mount.get("Name") == volume
                and mount.get("Destination") == "/workspace"
                and mount.get("RW") is False
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

    def _copy_junit(self, container: str, path: str) -> bytes | None:
        with tempfile.TemporaryDirectory(prefix="reproassert-junit-") as temporary:
            destination = Path(temporary) / "result.xml"
            result = self._control(
                ["cp", f"{container}:{path}", str(destination)],
                check=False,
                timeout_seconds=20,
            )
            if result.returncode != 0 or not destination.exists():
                return None
            metadata = destination.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
                return None
            return destination.read_bytes()

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
        self._control(["rm", "-f", name], check=False, timeout_seconds=20)
        self._containers.discard(name)

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


@dataclass(frozen=True)
class _AttachedResult:
    output: str
    output_truncated: bool
    timed_out: bool
    removed: bool


def _safe_token(value: str) -> str:
    token = "".join(character for character in value.lower() if character.isalnum())[:24]
    return token or uuid.uuid4().hex[:12]


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _sanitize_output(data: bytes) -> str:
    return sanitize_log(data.decode("utf-8", errors="replace"))
