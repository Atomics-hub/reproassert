"""Sandboxed execution in exact SWE-bench instance images."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntime,
    InstanceRuntimeManifest,
)
from reproassert.dependency_executor import (
    CommandResult,
    CommandRunner,
    SubprocessDockerRunner,
)
from reproassert.errors import PolicyRejection, ReproAssertError
from reproassert.sandbox import SandboxPolicy

MAX_STAGED_BYTES = 2 * 1024 * 1024
_CONTROL_OUTPUT_BYTES = 2 * 1024 * 1024
_LABEL_OWNER = "io.reproassert.instance-owner=controller-v1"
_SAFE_TARGET = re.compile(r"[A-Za-z0-9_./-]{1,300}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}\Z")
_CONTAINER_TMP = "/tmp"  # noqa: S108 - isolated container path, never a host path

_COPY_TESTBED_SCRIPT = """set -eu
cp -a /testbed/. /workspace/
cd /workspace
test "$(git rev-parse HEAD)" = "$1"
test "$(git rev-parse 'HEAD^{tree}')" = "$2"
test -z "$(git status --porcelain --untracked-files=no)"
""".strip()

_APPLY_PATCH_SCRIPT = """set -eu
test "$(sha256sum /tmp/reproassert-input | cut -d ' ' -f 1)" = "$1"
cd /workspace
git apply --check /tmp/reproassert-input
git apply /tmp/reproassert-input
test "$(git rev-parse HEAD)" = "$2"
""".strip()

_STAGE_CANDIDATE_SCRIPT = """set -eu
test "$(sha256sum /tmp/reproassert-input | cut -d ' ' -f 1)" = "$1"
cd /workspace
test ! -e "$2"
mkdir -p "$(dirname "$2")"
cp /tmp/reproassert-input "$2"
test "$(sha256sum "$2" | cut -d ' ' -f 1)" = "$1"
""".strip()

_PYTEST_SCRIPT = """set -eu
source /opt/miniconda3/bin/activate
conda activate testbed
cd /workspace
exec python -I -m pytest "$@"
""".strip()


@dataclass(frozen=True)
class InstanceWorkspaceSet:
    base_volume: str
    fixed_volume: str


@dataclass(frozen=True)
class InstancePytestResult:
    workspace: Literal["base", "fixed"]
    exit_code: int
    output: str
    timed_out: bool
    output_truncated: bool


class InstanceRuntimeExecutor:
    """Acquire one frozen image, prepare two isolated trees, and run fixed pytest argv."""

    def __init__(
        self,
        manifest: InstanceRuntimeManifest,
        *,
        case_id: str,
        policy: SandboxPolicy | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        matches = tuple(entry for entry in manifest.entries if entry.case_id == case_id)
        if len(matches) != 1:
            raise PolicyRejection(
                "benchmark_v02_instance_executor",
                "Case does not select exactly one frozen instance runtime.",
            )
        self.manifest = manifest
        self.runtime = matches[0]
        self.policy = policy or SandboxPolicy(image=self.runtime.image_id)
        if self.policy.image != self.runtime.image_id:
            raise PolicyRejection(
                "benchmark_v02_instance_executor", "Sandbox image must be the frozen image ID."
            )
        self.runner = runner or SubprocessDockerRunner()
        self._token = f"instance-{case_id}-{uuid.uuid4().hex[:12]}"
        self._volumes: dict[str, str] = {}
        self._containers: set[str] = set()
        self._acquired = False
        self._prepared = False

    def __enter__(self) -> InstanceRuntimeExecutor:
        return self

    def __exit__(self, *_args: object) -> Literal[False]:
        self.cleanup()
        return False

    def acquire(self) -> InstanceRuntime:
        """The only networked phase: pull one reviewed tag, then freeze its exact identity."""

        self._run(
            ["pull", "--platform", "linux/amd64", self.runtime.image_tag],
            timeout=900,
            max_output_bytes=_CONTROL_OUTPUT_BYTES,
        )
        inspection = self._inspect_image(self.runtime.image_tag)
        image_id = inspection.get("Id")
        os_name = inspection.get("Os")
        architecture = inspection.get("Architecture")
        repo_digests = inspection.get("RepoDigests")
        if not isinstance(repo_digests, list) or not all(
            isinstance(value, str) for value in repo_digests
        ):
            raise self._reject("Docker image has no repository digest evidence.")
        repository = self.runtime.image_tag.rsplit(":", 1)[0]
        expected_repo_digest = f"{repository}@{self.runtime.image_digest}"
        self.manifest.require(
            case_id=self.runtime.case_id,
            instance_id=self.runtime.instance_id,
            image_tag=self.runtime.image_tag,
            observed_image_digest=(
                self.runtime.image_digest if expected_repo_digest in repo_digests else ""
            ),
            observed_image_id=image_id if isinstance(image_id, str) else "",
            observed_platform=f"{os_name}/{architecture}",
        )
        self._acquired = True
        return self.runtime

    def prepare_workspaces(self, *, fixed_patch: bytes) -> InstanceWorkspaceSet:
        if not self._acquired or self._prepared:
            raise self._reject("Instance image must be acquired once before workspace preparation.")
        _bounded_bytes(fixed_patch, "fixed patch")
        for role in ("base", "fixed"):
            volume = f"reproassert-{self._token}-{role}"
            self._require_absent("volume", volume)
            result = self._run(
                [
                    "volume",
                    "create",
                    "--label",
                    _LABEL_OWNER,
                    "--label",
                    f"io.reproassert.instance-run={self._token}",
                    "--label",
                    f"io.reproassert.instance-role={role}",
                    volume,
                ],
                timeout=30,
            )
            if result.output.strip() != volume:
                raise self._reject("Docker created an unexpected workspace volume.")
            self._volumes[role] = volume
            self._copy_pristine_testbed(role)
        self._stage_bytes("fixed", fixed_patch, purpose="patch")
        self._prepared = True
        return InstanceWorkspaceSet(
            base_volume=self._volumes["base"], fixed_volume=self._volumes["fixed"]
        )

    def stage_candidate(self, *, relative_path: str, content: bytes) -> None:
        if not self._prepared:
            raise self._reject("Instance workspaces are not prepared.")
        target = _relative_target(relative_path, "candidate path")
        _bounded_bytes(content, "candidate")
        for role in ("base", "fixed"):
            self._stage_bytes(role, content, purpose="candidate", relative_path=target)

    def run_pytest(
        self,
        *,
        workspace: Literal["base", "fixed"],
        target: str,
        collect_only: bool = False,
    ) -> InstancePytestResult:
        if not self._prepared or workspace not in self._volumes:
            raise self._reject("Requested instance workspace is unavailable.")
        checked_target = _relative_target(target, "pytest target")
        command = [
            "/bin/bash",
            "-c",
            _PYTEST_SCRIPT,
            "reproassert-pytest",
            *(["--collect-only"] if collect_only else []),
            checked_target,
        ]
        name = self._create_sandbox_container(workspace, command, role=f"pytest-{workspace}")
        try:
            result = self._run(
                ["start", "--attach", name],
                timeout=self.policy.timeout_seconds,
                max_output_bytes=self.policy.max_output_bytes,
                allow_failure=True,
            )
            return InstancePytestResult(
                workspace=workspace,
                exit_code=result.returncode,
                output=result.output,
                timed_out=result.timed_out,
                output_truncated=result.output_truncated,
            )
        finally:
            self._remove_container(name)

    def cleanup(self) -> None:
        errors: list[str] = []
        for name in tuple(self._containers):
            try:
                self._remove_container(name)
            except ReproAssertError as exc:
                errors.append(exc.message)
        for role, volume in tuple(self._volumes.items()):
            try:
                self._run(["volume", "rm", volume], timeout=30)
                self._volumes.pop(role, None)
            except ReproAssertError as exc:
                errors.append(exc.message)
        if errors:
            raise self._reject("Instance runtime cleanup failed: " + "; ".join(errors))

    def _copy_pristine_testbed(self, role: str) -> None:
        command = [
            "/bin/bash",
            "-c",
            _COPY_TESTBED_SCRIPT,
            "reproassert-copy",
            self.runtime.base_sha,
            self.runtime.base_tree_oid,
        ]
        name = self._create_sandbox_container(role, command, role=f"copy-{role}")
        try:
            self._run(["start", "--attach", name], timeout=300)
        finally:
            self._remove_container(name)

    def _stage_bytes(
        self,
        workspace: str,
        content: bytes,
        *,
        purpose: Literal["patch", "candidate"],
        relative_path: str | None = None,
    ) -> None:
        digest = hashlib.sha256(content).hexdigest()
        script = _APPLY_PATCH_SCRIPT if purpose == "patch" else _STAGE_CANDIDATE_SCRIPT
        arguments = (
            [digest, self.runtime.base_sha] if purpose == "patch" else [digest, relative_path]
        )
        command = ["/bin/bash", "-c", script, f"reproassert-{purpose}", *cast(list[str], arguments)]
        name = self._create_sandbox_container(
            workspace, command, role=f"stage-{purpose}-{workspace}"
        )
        try:
            with tempfile.TemporaryDirectory(prefix="reproassert-instance-") as temporary:
                os.chmod(temporary, 0o700)
                source = Path(temporary) / "input"
                source.write_bytes(content)
                source.chmod(0o600)
                self._run(["cp", str(source), f"{name}:/tmp/reproassert-input"], timeout=30)
            self._run(["start", "--attach", name], timeout=120)
        finally:
            self._remove_container(name)

    def _create_sandbox_container(
        self,
        workspace: str,
        command: list[str],
        *,
        role: str,
        read_only: bool = True,
    ) -> str:
        volume = self._volumes[workspace]
        name = f"reproassert-{self._token}-{role}-{uuid.uuid4().hex[:8]}"
        args = [
            "create",
            "--name",
            name,
            "--label",
            _LABEL_OWNER,
            "--label",
            f"io.reproassert.instance-run={self._token}",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self.policy.pids),
            "--memory",
            str(self.policy.memory_bytes),
            "--memory-swap",
            str(self.policy.memory_bytes),
            "--cpus",
            _cpu_text(self.policy.cpus),
            "--user",
            "0:0",
            "--tmpfs",
            f"{_CONTAINER_TMP}:rw,noexec,nosuid,nodev,size={self.policy.tmpfs_bytes},nr_inodes={self.policy.tmpfs_inodes}",
            "--mount",
            f"type=volume,src={volume},dst=/workspace",
        ]
        if read_only:
            args.append("--read-only")
        args.extend(["--entrypoint", command[0], self.runtime.image_id, *command[1:]])
        result = self._run(args, timeout=30)
        container_id = result.output.strip()
        if _CONTAINER_ID.fullmatch(container_id) is None:
            raise self._reject("Docker returned an invalid instance container ID.")
        self._containers.add(name)
        self._inspect_container_policy(name, volume, command=command, read_only=read_only)
        return name

    def _inspect_container_policy(
        self, name: str, volume: str, *, command: list[str], read_only: bool
    ) -> None:
        payload = self._inspect_one(["container", "inspect", name], "container")
        config = _mapping(payload.get("Config"), "container config")
        host = _mapping(payload.get("HostConfig"), "container host config")
        mounts = payload.get("Mounts")
        security_options = host.get("SecurityOpt")
        expected_tmpfs = {
            _CONTAINER_TMP: (
                "rw,noexec,nosuid,nodev,"
                f"size={self.policy.tmpfs_bytes},nr_inodes={self.policy.tmpfs_inodes}"
            )
        }
        expected_nano_cpus = int(self.policy.cpus * 1_000_000_000)
        valid_mount = (
            isinstance(mounts, list)
            and len(mounts) == 1
            and isinstance(mounts[0], dict)
            and mounts[0].get("Type") == "volume"
            and mounts[0].get("Name") == volume
            and mounts[0].get("Destination") == "/workspace"
            and mounts[0].get("RW") is True
        )
        if not (
            payload.get("Image") == self.runtime.image_id
            and config.get("User") == "0:0"
            and config.get("Entrypoint") == [command[0]]
            and config.get("Cmd") == command[1:]
            and host.get("NetworkMode") == "none"
            and host.get("ReadonlyRootfs") is read_only
            and host.get("CapDrop") == ["ALL"]
            and isinstance(security_options, list)
            and "no-new-privileges" in security_options
            and host.get("PidsLimit") == self.policy.pids
            and host.get("Memory") == self.policy.memory_bytes
            and host.get("MemorySwap") == self.policy.memory_bytes
            and host.get("NanoCpus") == expected_nano_cpus
            and host.get("Tmpfs") == expected_tmpfs
            and not host.get("Binds")
            and valid_mount
        ):
            raise self._reject("Effective instance container policy differs from the request.")

    def _inspect_image(self, reference: str) -> dict[str, object]:
        return self._inspect_one(["image", "inspect", reference], "image")

    def _inspect_one(self, args: list[str], label: str) -> dict[str, object]:
        result = self._run(args, timeout=20)
        try:
            value = json.loads(result.output)
        except json.JSONDecodeError as exc:
            raise self._reject(f"Docker returned invalid {label} inspection JSON.") from exc
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise self._reject(f"Docker returned invalid {label} inspection evidence.")
        return cast(dict[str, object], value[0])

    def _require_absent(self, kind: str, name: str) -> None:
        result = self.runner.run(
            [kind, "inspect", name], timeout_seconds=10, max_output_bytes=64 * 1024
        )
        if result.returncode == 0:
            raise self._reject(f"Refusing to reuse a pre-existing {kind}.")

    def _remove_container(self, name: str) -> None:
        if name not in self._containers:
            return
        self._run(["container", "rm", "--force", name], timeout=30)
        self._containers.discard(name)

    def _run(
        self,
        args: list[str],
        *,
        timeout: float,
        max_output_bytes: int = 256 * 1024,
        allow_failure: bool = False,
    ) -> CommandResult:
        result = self.runner.run(args, timeout_seconds=timeout, max_output_bytes=max_output_bytes)
        if not allow_failure and (
            result.returncode != 0 or result.timed_out or result.output_truncated
        ):
            raise self._reject("Bounded Docker instance-runtime command failed.")
        return result

    @staticmethod
    def _reject(message: str) -> ReproAssertError:
        return ReproAssertError("benchmark_v02_instance_executor", message)


def _relative_target(value: str, label: str) -> str:
    if not isinstance(value, str) or _SAFE_TARGET.fullmatch(value) is None or value.startswith("-"):
        raise PolicyRejection(
            "benchmark_v02_instance_executor", f"{label.capitalize()} is invalid."
        )
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PolicyRejection("benchmark_v02_instance_executor", f"{label.capitalize()} is unsafe.")
    return value


def _bounded_bytes(value: bytes, label: str) -> None:
    if not isinstance(value, bytes) or not 1 <= len(value) <= MAX_STAGED_BYTES:
        raise PolicyRejection(
            "benchmark_v02_instance_executor", f"{label.capitalize()} bytes are outside policy."
        )


def _cpu_text(value: float) -> str:
    if not math.isfinite(value) or value <= 0:
        raise ValueError("CPU limit is invalid")
    return format(value, ".6g")


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReproAssertError("benchmark_v02_instance_executor", f"Docker {label} is invalid.")
    return cast(dict[str, object], value)
