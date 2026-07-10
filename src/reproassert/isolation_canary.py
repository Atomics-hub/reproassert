from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import tempfile
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from reproassert import __version__
from reproassert.errors import ReproAssertError
from reproassert.sandbox import OWNER_LABEL, RUN_LABEL, DockerSandbox, SandboxPolicy

CANARY_VERSION = "reproassert-generator-evaluator-isolation-v1"
EVALUATOR_DESTINATION = "/evaluator"
GENERATOR_DESTINATION = "/workspace"
POSITIVE_MARKER = "REPROASSERT_CANARY_POSITIVE_OK"
NEGATIVE_MARKER = "REPROASSERT_CANARY_NEGATIVE_OK"
CANARY_USER = "65532:65532"

_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PROCESS_ENVIRONMENT = (
    "HOME=/tmp/home",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "PATH=/usr/local/bin:/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE=1",
    "PYTHONHASHSEED=0",
    "TZ=UTC",
)
_POSITIVE_SCRIPT = """
import hashlib
import os
import stat
import sys

path = "/evaluator/sentinel"
metadata = os.lstat(path)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
    raise SystemExit(20)
with open(path, "rb") as stream:
    content = stream.read(4097)
if len(content) > 4096 or hashlib.sha256(content).hexdigest() != sys.argv[1]:
    raise SystemExit(21)
print("REPROASSERT_CANARY_POSITIVE_OK")
""".strip()
_NEGATIVE_SCRIPT = """
import hashlib
import os
import stat
import sys

expected = sys.argv[1]
for forbidden in ("/evaluator", "/evaluator/sentinel"):
    if os.path.lexists(forbidden):
        raise SystemExit(30)
files = 0
total = 0
for root, directories, names in os.walk("/workspace", topdown=True, followlinks=False):
    directories.sort()
    names.sort()
    for directory in directories:
        if stat.S_ISLNK(os.lstat(os.path.join(root, directory)).st_mode):
            raise SystemExit(31)
    for name in names:
        path = os.path.join(root, name)
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(32)
        files += 1
        total += metadata.st_size
        if files > 32 or total > 1048576:
            raise SystemExit(33)
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
        if digest.hexdigest() == expected:
            raise SystemExit(34)
print("REPROASSERT_CANARY_NEGATIVE_OK")
""".strip()


@dataclass(frozen=True)
class IsolationCanaryResult:
    version: str
    tool_version: str
    tool_git_sha: str | None
    policy_sha256: str
    config_sha256: str
    image_id: str
    sentinel_sha256: str
    positive_control_passed: bool
    negative_control_passed: bool
    positive_mount_destinations: tuple[str, ...]
    generator_mount_destinations: tuple[str, ...]
    process_env_names: tuple[str, ...]
    image_env_names_cleared: tuple[str, ...]
    cleanup_succeeded: bool

    @property
    def accepted(self) -> bool:
        return (
            self.positive_control_passed and self.negative_control_passed and self.cleanup_succeeded
        )


def run_isolation_canary(
    sandbox: DockerSandbox | None = None,
    *,
    tool_git_sha: str | None = None,
) -> IsolationCanaryResult:
    """Exercise a standalone synthetic generator/evaluator mount policy.

    The sentinel value never enters a command, log, exception, or result. Only its SHA-256 digest
    crosses the controller/container boundary.
    """

    boundary = sandbox or DockerSandbox()
    if tool_git_sha is not None and re.fullmatch(r"[0-9a-f]{40}", tool_git_sha) is None:
        raise ReproAssertError(
            "isolation_canary_revision", "Tool Git SHA must be 40 lowercase hexadecimal digits."
        )
    _validate_policy(boundary.policy)
    status = boundary.require_ready()
    image_id = status.image_id
    if image_id is None or _IMAGE_ID.fullmatch(image_id) is None:
        raise ReproAssertError(
            "isolation_canary_image", "Docker returned an invalid sandbox image ID."
        )
    image_environment = _inspect_image_environment(boundary, image_id)

    sentinel = secrets.token_bytes(32)
    sentinel_sha256 = hashlib.sha256(sentinel).hexdigest()
    run_id = uuid.uuid4().hex
    evaluator_volume = f"reproassert-canary-evaluator-{run_id[:12]}"
    source_volume = f"reproassert-canary-source-{run_id[:12]}"
    containers: set[str] = set()
    volumes: set[str] = set()

    positive_passed = False
    negative_passed = False
    cleanup_succeeded = False
    try:
        with tempfile.TemporaryDirectory(prefix="reproassert-canary-") as temporary:
            root = Path(temporary)
            evaluator_source = root / "evaluator"
            generator_source = root / "source"
            evaluator_source.mkdir(mode=0o700)
            generator_source.mkdir(mode=0o700)
            sentinel_path = evaluator_source / "sentinel"
            sentinel_path.write_bytes(sentinel)
            sentinel_path.chmod(0o444)
            source_path = generator_source / "source.txt"
            source_path.write_text("synthetic generator-visible source\n", encoding="utf-8")
            source_path.chmod(0o444)

            _stage_volume(
                boundary,
                volume=evaluator_volume,
                source=evaluator_source,
                destination=EVALUATOR_DESTINATION,
                run_id=run_id,
                containers=containers,
                volumes=volumes,
            )
            _stage_volume(
                boundary,
                volume=source_volume,
                source=generator_source,
                destination=GENERATOR_DESTINATION,
                run_id=run_id,
                containers=containers,
                volumes=volumes,
            )

            positive_passed = _run_control(
                boundary,
                role="positive",
                volume=evaluator_volume,
                destination=EVALUATOR_DESTINATION,
                script=_POSITIVE_SCRIPT,
                expected_marker=POSITIVE_MARKER,
                sentinel_sha256=sentinel_sha256,
                image_id=image_id,
                image_environment=image_environment,
                run_id=run_id,
                containers=containers,
            )
            negative_passed = _run_control(
                boundary,
                role="generator",
                volume=source_volume,
                destination=GENERATOR_DESTINATION,
                script=_NEGATIVE_SCRIPT,
                expected_marker=NEGATIVE_MARKER,
                sentinel_sha256=sentinel_sha256,
                image_id=image_id,
                image_environment=image_environment,
                run_id=run_id,
                containers=containers,
            )
    finally:
        sentinel = b""
        cleanup_succeeded = _cleanup(boundary, containers=containers, volumes=volumes)

    policy_sha256 = _json_sha256(asdict(boundary.policy))
    config_sha256 = _json_sha256(
        _configuration_record(
            boundary.policy,
            image_id=image_id,
            image_environment=image_environment,
            policy_sha256=policy_sha256,
            tool_git_sha=tool_git_sha,
        )
    )
    return IsolationCanaryResult(
        version=CANARY_VERSION,
        tool_version=__version__,
        tool_git_sha=tool_git_sha,
        policy_sha256=policy_sha256,
        config_sha256=config_sha256,
        image_id=image_id,
        sentinel_sha256=sentinel_sha256,
        positive_control_passed=positive_passed,
        negative_control_passed=negative_passed,
        positive_mount_destinations=(EVALUATOR_DESTINATION,),
        generator_mount_destinations=(GENERATOR_DESTINATION,),
        process_env_names=tuple(value.partition("=")[0] for value in _PROCESS_ENVIRONMENT),
        image_env_names_cleared=tuple(sorted(_environment_names(image_environment))),
        cleanup_succeeded=cleanup_succeeded,
    )


def _validate_policy(policy: SandboxPolicy) -> None:
    values = (
        policy.timeout_seconds,
        policy.cpus,
        policy.max_output_bytes,
        policy.memory_bytes,
        policy.pids,
        policy.tmpfs_bytes,
        policy.tmpfs_inodes,
    )
    if any(
        not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0
        for value in values
    ):
        raise ReproAssertError(
            "isolation_canary_policy", "Isolation canary limits must be finite and positive."
        )


def _inspect_image_environment(boundary: DockerSandbox, image_id: str) -> tuple[str, ...]:
    result = boundary._control(["image", "inspect", boundary.policy.image], timeout_seconds=20)
    try:
        values = json.loads(result.stdout)
        if len(values) != 1 or not isinstance(values[0], dict):
            raise ValueError
        inspected = values[0]
        if inspected.get("Id") != image_id:
            raise ValueError
        config = inspected.get("Config")
        if not isinstance(config, dict):
            raise ValueError
        environment = config.get("Env") or []
        if not isinstance(environment, list) or not all(
            isinstance(value, str) and "=" in value for value in environment
        ):
            raise ValueError
        names = _environment_names(tuple(environment))
        if len(names) != len(environment):
            raise ValueError
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ReproAssertError(
            "isolation_canary_image", "Docker returned invalid sandbox image metadata."
        ) from exc
    return tuple(environment)


def _stage_volume(
    boundary: DockerSandbox,
    *,
    volume: str,
    source: Path,
    destination: str,
    run_id: str,
    containers: set[str],
    volumes: set[str],
) -> None:
    boundary._control(
        [
            "volume",
            "create",
            "--label",
            f"{RUN_LABEL}={run_id}",
            "--label",
            OWNER_LABEL,
            volume,
        ],
        timeout_seconds=30,
    )
    volumes.add(volume)
    name = f"reproassert-canary-stage-{uuid.uuid4().hex[:12]}"
    boundary._control(
        [
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
            CANARY_USER,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--mount",
            f"type=volume,src={volume},dst={destination}",
            "--entrypoint",
            "/bin/true",
            boundary.policy.image,
        ],
        timeout_seconds=30,
    )
    containers.add(name)
    try:
        boundary._control(["cp", "-a", f"{source}/.", f"{name}:{destination}/"], timeout_seconds=30)
    finally:
        _remove_container(boundary, name=name, containers=containers)


def _run_control(
    boundary: DockerSandbox,
    *,
    role: str,
    volume: str,
    destination: str,
    script: str,
    expected_marker: str,
    sentinel_sha256: str,
    image_id: str,
    image_environment: tuple[str, ...],
    run_id: str,
    containers: set[str],
) -> bool:
    name = f"reproassert-canary-{role}-{uuid.uuid4().hex[:12]}"
    process_args = ("/usr/local/bin/python", "-I", "-c", script, sentinel_sha256)
    boundary._control(
        _create_args(
            boundary.policy,
            name=name,
            volume=volume,
            destination=destination,
            run_id=run_id,
            process_args=process_args,
        ),
        timeout_seconds=30,
    )
    containers.add(name)
    try:
        inspected = boundary._inspect(name)
        _assert_container_policy(
            inspected,
            policy=boundary.policy,
            image_id=image_id,
            image_environment=image_environment,
            volume=volume,
            destination=destination,
            process_args=process_args,
        )
        attached = boundary._start_attached(name)
        if attached.removed or attached.timed_out or attached.output_truncated:
            return False
        state = boundary._container_state(name)
        return state.get("ExitCode") == 0 and attached.output.strip() == expected_marker
    finally:
        _remove_container(boundary, name=name, containers=containers)


def _create_args(
    policy: SandboxPolicy,
    *,
    name: str,
    volume: str,
    destination: str,
    run_id: str,
    process_args: tuple[str, ...],
) -> list[str]:
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
        CANARY_USER,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        str(policy.pids),
        "--memory",
        str(policy.memory_bytes),
        "--memory-swap",
        str(policy.memory_bytes),
        "--cpus",
        str(policy.cpus),
        "--ulimit",
        "nofile=256:256",
        "--ulimit",
        "core=0:0",
        "--ulimit",
        "fsize=1048576:1048576",
        "--shm-size",
        "16m",
        "--init",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={policy.tmpfs_bytes},nr_inodes={policy.tmpfs_inodes}",  # noqa: S108 - container tmpfs
        "--mount",
        f"type=volume,src={volume},dst={destination},readonly",
        "--workdir",
        "/",
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
        policy.image,
        "-i",
        *_PROCESS_ENVIRONMENT,
        *process_args,
    ]


def _assert_container_policy(
    inspected: dict[str, Any],
    *,
    policy: SandboxPolicy,
    image_id: str,
    image_environment: tuple[str, ...],
    volume: str,
    destination: str,
    process_args: tuple[str, ...],
) -> None:
    host = inspected.get("HostConfig")
    config = inspected.get("Config")
    mounts = inspected.get("Mounts")
    if not isinstance(host, dict) or not isinstance(config, dict) or not isinstance(mounts, list):
        raise ReproAssertError(
            "isolation_canary_policy", "Docker returned incomplete canary policy metadata."
        )
    expected_command = ["-i", *_PROCESS_ENVIRONMENT, *process_args]
    expected_tmpfs = (
        f"rw,noexec,nosuid,nodev,size={policy.tmpfs_bytes},nr_inodes={policy.tmpfs_inodes}"
    )
    security = set(host.get("SecurityOpt") or [])
    cap_drop = {str(value).upper() for value in host.get("CapDrop") or []}
    log_config = host.get("LogConfig") or {}
    checks = {
        "image_id": inspected.get("Image") == image_id,
        "network_none": host.get("NetworkMode") == "none",
        "readonly_root": host.get("ReadonlyRootfs") is True,
        "non_root": config.get("User") == CANARY_USER,
        "caps_dropped": "ALL" in cap_drop and not host.get("CapAdd"),
        "no_new_privileges": "no-new-privileges=true" in security,
        "not_privileged": host.get("Privileged") is False,
        "pid_private": not host.get("PidMode"),
        "ipc_private": host.get("IpcMode") in ("private", ""),
        "pids": host.get("PidsLimit") == policy.pids,
        "memory": host.get("Memory") == policy.memory_bytes,
        "memory_swap": host.get("MemorySwap") == policy.memory_bytes,
        "cpus": host.get("NanoCpus") == int(policy.cpus * 1_000_000_000),
        "no_devices": not host.get("Devices"),
        "no_binds": not host.get("Binds"),
        "tmpfs": (host.get("Tmpfs") or {}).get("/tmp")  # noqa: S108 - container tmpfs
        == expected_tmpfs,
        "bounded_logs": log_config.get("Type") == "local"
        and log_config.get("Config") == {"max-size": "128k", "max-file": "1", "compress": "false"},
        "exact_mount": len(mounts) == 1
        and mounts[0].get("Type") == "volume"
        and mounts[0].get("Name") == volume
        and mounts[0].get("Destination") == destination
        and mounts[0].get("RW") is False,
        "image_env_unchanged": tuple(config.get("Env") or ()) == image_environment,
        "cleared_process_env": config.get("Entrypoint") == ["/usr/bin/env"]
        and config.get("Cmd") == expected_command,
    }
    failed = sorted(key for key, passed in checks.items() if not passed)
    if failed:
        raise ReproAssertError(
            "isolation_canary_policy", "Docker did not apply canary policy: " + ", ".join(failed)
        )


def _remove_container(boundary: DockerSandbox, *, name: str, containers: set[str]) -> bool:
    result = boundary._control(["rm", "-f", name], check=False, timeout_seconds=20)
    if result.returncode == 0:
        containers.discard(name)
        boundary._containers.discard(name)
        return True
    return False


def _cleanup(boundary: DockerSandbox, *, containers: set[str], volumes: set[str]) -> bool:
    succeeded = True
    for name in tuple(containers):
        succeeded = _remove_container(boundary, name=name, containers=containers) and succeeded
    for volume in tuple(volumes):
        result = boundary._control(["volume", "rm", "-f", volume], check=False, timeout_seconds=30)
        if result.returncode == 0:
            volumes.discard(volume)
            boundary._volumes.discard(volume)
        else:
            succeeded = False
    return succeeded and not containers and not volumes


def _environment_names(environment: tuple[str, ...]) -> set[str]:
    return {value.partition("=")[0] for value in environment}


def _configuration_record(
    policy: SandboxPolicy,
    *,
    image_id: str,
    image_environment: tuple[str, ...],
    policy_sha256: str,
    tool_git_sha: str | None,
) -> dict[str, object]:
    return {
        "version": CANARY_VERSION,
        "tool": {
            "name": "reproassert",
            "version": __version__,
            "git_sha": tool_git_sha,
        },
        "image": policy.image,
        "image_id": image_id,
        "image_environment_sha256": _json_sha256(list(image_environment)),
        "policy_sha256": policy_sha256,
        "container_policy": {
            "pull": "never",
            "network": "none",
            "root_filesystem": "read_only",
            "user": CANARY_USER,
            "cap_drop": ["ALL"],
            "cap_add": [],
            "security_options": ["no-new-privileges=true"],
            "privileged": False,
            "pid_mode": "private",
            "ipc_mode": "private",
            "pids": policy.pids,
            "memory_bytes": policy.memory_bytes,
            "memory_swap_bytes": policy.memory_bytes,
            "cpus": policy.cpus,
            "ulimits": ["nofile=256:256", "core=0:0", "fsize=1048576:1048576"],
            "shm_bytes": 16 * 1024 * 1024,
            "tmpfs": {
                "destination": "/tmp",  # noqa: S108 - container path
                "options": (
                    "rw,noexec,nosuid,nodev,"
                    f"size={policy.tmpfs_bytes},nr_inodes={policy.tmpfs_inodes}"
                ),
            },
            "mount_type": "volume",
            "mount_read_only": True,
            "positive_destination": EVALUATOR_DESTINATION,
            "generator_destination": GENERATOR_DESTINATION,
            "workdir": "/",
            "log_driver": "local",
            "log_options": {"max-size": "128k", "max-file": "1", "compress": "false"},
            "entrypoint": "/usr/bin/env",
            "process_environment_clear": True,
            "process_environment": list(_PROCESS_ENVIRONMENT),
        },
        "positive_script_sha256": hashlib.sha256(_POSITIVE_SCRIPT.encode()).hexdigest(),
        "negative_script_sha256": hashlib.sha256(_NEGATIVE_SCRIPT.encode()).hexdigest(),
    }


def _json_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
