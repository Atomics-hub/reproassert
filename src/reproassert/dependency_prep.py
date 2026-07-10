from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath
from typing import Any

from reproassert import __version__
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file
from reproassert.sandbox import SandboxPolicy
from reproassert.source_attestation import SOURCE_TREE_ALGORITHM, SourceTreeAttestation

DEPENDENCY_PLAN_SCHEMA_VERSION = "0.1.0"
DEPENDENCY_RECEIPT_SCHEMA_VERSION = "0.1.0"
DEPENDENCY_POLICY_ID = "pypi-hash-locked-wheels-v1"
EVALUATOR_PACKAGE_ALGORITHM = "reproassert-evaluator-package-v1"
WHEELHOUSE_ALGORITHM = "reproassert-wheelhouse-v1"

PYPI_INDEX_URL = "https://pypi.org/simple"
PYPI_ARTIFACT_HOST = "files.pythonhosted.org"
MAX_PLAN_BYTES = 512 * 1024
MAX_PACKAGES = 256
MAX_HASHES_PER_PACKAGE = 32
MAX_WHEELS = 256
MAX_WHEEL_BYTES = 128 * 1024 * 1024
MAX_WHEELHOUSE_BYTES = 512 * 1024 * 1024
MAX_WHEEL_MEMBERS = 20_000
MAX_WHEEL_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_WHEELHOUSE_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 256 * 1024
MAX_JSON_NESTING = 64

_CASE_ID = re.compile(r"rk-v(?:0\.1|0\.2)-[0-9]{3}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_PACKAGE_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}")
_PYTHON_VERSION = re.compile(r"3\.[0-9]{1,2}(?:\.[0-9]{1,2})?")
_IMAGE_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,199}")
_DOCKER_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_WHEEL_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,249}\.whl")

_PLAN_KEYS = {
    "schema_version",
    "case_id",
    "source",
    "runtime",
    "index_policy",
    "packages",
}
_SOURCE_KEYS = {"base_sha", "tree_sha256"}
_RUNTIME_KEYS = {"python_version", "runner_image"}
_PACKAGE_KEYS = {"name", "version", "sha256"}


@dataclass(frozen=True)
class LockedPackage:
    name: str
    version: str
    sha256: tuple[str, ...]


@dataclass(frozen=True)
class DependencyPlan:
    case_id: str
    base_sha: str
    source_tree_sha256: str
    python_version: str
    runner_image: str
    packages: tuple[LockedPackage, ...]
    raw_sha256: str
    canonical_sha256: str


@dataclass(frozen=True)
class WheelArtifact:
    package: str
    version: str
    filename: str
    sha256: str
    bytes: int
    unpacked_bytes: int


@dataclass(frozen=True)
class WheelhouseAttestation:
    algorithm: str
    sha256: str
    file_count: int
    total_bytes: int
    total_unpacked_bytes: int
    files: tuple[WheelArtifact, ...]


def load_dependency_plan(path: Path) -> DependencyPlan:
    """Load a duplicate-key-free, hash-complete, wheel-only preparation plan."""

    raw = _read_bounded_regular(path, MAX_PLAN_BYTES, "dependency plan")
    decoded = _decode_strict_json(raw, "dependency plan")
    root = _exact_object(decoded, _PLAN_KEYS, "dependency plan")
    _require_equal(root.get("schema_version"), DEPENDENCY_PLAN_SCHEMA_VERSION, "schema version")

    case_id = _ascii_pattern(root.get("case_id"), "case id", _CASE_ID)
    source = _exact_object(root.get("source"), _SOURCE_KEYS, "dependency plan source")
    base_sha = _ascii_pattern(source.get("base_sha"), "base SHA", _GIT_SHA)
    source_tree_sha256 = _ascii_pattern(source.get("tree_sha256"), "source tree SHA-256", _SHA256)

    runtime = _exact_object(root.get("runtime"), _RUNTIME_KEYS, "dependency plan runtime")
    python_version = _ascii_pattern(
        runtime.get("python_version"), "Python version", _PYTHON_VERSION
    )
    runner_image = _ascii_pattern(runtime.get("runner_image"), "runner image", _IMAGE_REFERENCE)
    _require_equal(root.get("index_policy"), DEPENDENCY_POLICY_ID, "index policy")

    package_values = root.get("packages")
    if not isinstance(package_values, list) or not 1 <= len(package_values) <= MAX_PACKAGES:
        raise _rejection(f"Dependency plan must contain 1-{MAX_PACKAGES} packages.")
    packages: list[LockedPackage] = []
    seen_names: set[str] = set()
    for position, value in enumerate(package_values, start=1):
        package = _exact_object(value, _PACKAGE_KEYS, f"dependency package {position}")
        name = _ascii_pattern(package.get("name"), "normalized package name", _PACKAGE_NAME)
        version = _ascii_pattern(package.get("version"), "package version", _VERSION)
        hashes_value = package.get("sha256")
        if (
            not isinstance(hashes_value, list)
            or not 1 <= len(hashes_value) <= MAX_HASHES_PER_PACKAGE
        ):
            raise _rejection(
                f"Package {name!r} must contain 1-{MAX_HASHES_PER_PACKAGE} SHA-256 hashes."
            )
        hashes = tuple(
            _ascii_pattern(value, f"package {name} SHA-256", _SHA256) for value in hashes_value
        )
        if hashes != tuple(sorted(set(hashes))):
            raise _rejection(f"Package {name!r} hashes must be unique and sorted.")
        if name in seen_names:
            raise _rejection(f"Dependency plan repeats package {name!r}.")
        seen_names.add(name)
        packages.append(LockedPackage(name=name, version=version, sha256=hashes))
    if packages != sorted(packages, key=lambda item: item.name):
        raise _rejection("Dependency packages must be sorted by normalized name.")

    canonical_payload = {
        "schema_version": DEPENDENCY_PLAN_SCHEMA_VERSION,
        "case_id": case_id,
        "source": {"base_sha": base_sha, "tree_sha256": source_tree_sha256},
        "runtime": {"python_version": python_version, "runner_image": runner_image},
        "index_policy": DEPENDENCY_POLICY_ID,
        "packages": [asdict(package) for package in packages],
    }
    return DependencyPlan(
        case_id=case_id,
        base_sha=base_sha,
        source_tree_sha256=source_tree_sha256,
        python_version=python_version,
        runner_image=runner_image,
        packages=tuple(packages),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        canonical_sha256=hashlib.sha256(_canonical_json_bytes(canonical_payload)).hexdigest(),
    )


def render_requirements_lock(plan: DependencyPlan) -> bytes:
    """Render the only requirements input accepted by the preparation containers."""

    lines = []
    for package in plan.packages:
        hashes = " ".join(f"--hash=sha256:{value}" for value in package.sha256)
        lines.append(f"{package.name}=={package.version} {hashes}")
    return ("\n".join(lines) + "\n").encode("ascii")


def dependency_preparation_policy(policy: SandboxPolicy | None = None) -> dict[str, object]:
    """Return the concrete policy committed by a dependency receipt.

    The initial local profile constrains destinations through trusted pip argv and
    post-download hashes. Docker bridge networking does not enforce an egress
    allowlist; the receipt names that residual limitation instead of hiding it.
    """

    active = policy or SandboxPolicy()
    return {
        "id": DEPENDENCY_POLICY_ID,
        "network_acquisition": {
            "phase": "trusted_pip_wheel_download_only",
            "docker_network_mode": "bridge",
            "index_url": PYPI_INDEX_URL,
            "expected_artifact_host": PYPI_ARTIFACT_HOST,
            "egress_enforcement": "fixed_pip_argv_and_post_download_hashes_not_network_acl",
            "source_mounted": False,
            "credentials": "none",
            "proxies": "cleared",
            "requirements": "controller_rendered_exact_versions_and_sha256",
            "dependencies": "complete_reviewed_closure_no_resolver",
            "artifacts": "binary_wheels_only",
        },
        "offline_install": {
            "network": "none",
            "index": "disabled",
            "dependencies": "disabled",
            "source_builds": "disabled",
            "bytecode_compile": "disabled",
            "wheelhouse": "read_only",
            "output": "controller_owned_volume",
        },
        "verification": {
            "network": "none",
            "dependencies_mount": "read_only_at_/dependencies",
            "fresh_container_per_execution": True,
        },
        "container": {
            "image": active.image,
            "read_only_root": True,
            "user": "65532:65532",
            "capabilities": "drop_all",
            "no_new_privileges": True,
            "host_bind_mounts": False,
            "docker_socket": False,
            "environment": "cleared_allowlist_only",
            "pids": active.pids,
            "memory_bytes": active.memory_bytes,
            "cpus": active.cpus,
            "tmpfs_bytes": active.tmpfs_bytes,
            "tmpfs_inodes": active.tmpfs_inodes,
            "timeout_seconds": active.timeout_seconds,
            "max_output_bytes": active.max_output_bytes,
        },
        "artifact_limits": {
            "max_packages": MAX_PACKAGES,
            "max_wheels": MAX_WHEELS,
            "max_wheel_bytes": MAX_WHEEL_BYTES,
            "max_wheelhouse_bytes": MAX_WHEELHOUSE_BYTES,
            "max_wheel_members": MAX_WHEEL_MEMBERS,
            "max_wheel_unpacked_bytes": MAX_WHEEL_UNPACKED_BYTES,
            "max_wheelhouse_unpacked_bytes": MAX_WHEELHOUSE_UNPACKED_BYTES,
            "max_metadata_bytes": MAX_METADATA_BYTES,
        },
    }


def dependency_download_create_args(
    plan: DependencyPlan,
    *,
    name: str,
    input_volume: str,
    wheelhouse_volume: str,
    run_id: str,
    policy: SandboxPolicy | None = None,
) -> list[str]:
    """Build fixed Docker argv for the sole network-enabled phase.

    The input volume contains only ``requirements.lock`` rendered by the
    controller. The repository source and dependency output are absent.
    """

    active = policy or SandboxPolicy(image=plan.runner_image)
    _require_policy_image(plan, active)
    _require_docker_token(input_volume, "input volume")
    _require_docker_token(wheelhouse_volume, "wheelhouse volume")
    args = _base_create_args(
        active,
        name=name,
        run_id=run_id,
        network="bridge",
    )
    args.extend(
        [
            "--mount",
            f"type=volume,src={input_volume},dst=/input,readonly",
            "--mount",
            f"type=volume,src={wheelhouse_volume},dst=/wheelhouse",
            "--workdir",
            "/tmp",  # noqa: S108 - path is inside the preparation container
            "--entrypoint",
            "/usr/bin/env",
            active.image,
            "-i",
            *_pip_environment(),
            "/usr/local/bin/python",
            "-m",
            "pip",
            "download",
            "--disable-pip-version-check",
            "--no-input",
            "--no-cache-dir",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "--index-url",
            PYPI_INDEX_URL,
            "--dest",
            "/wheelhouse",
            "--requirement",
            "/input/requirements.lock",
        ]
    )
    return args


def dependency_install_create_args(
    plan: DependencyPlan,
    *,
    name: str,
    input_volume: str,
    wheelhouse_volume: str,
    dependency_volume: str,
    run_id: str,
    policy: SandboxPolicy | None = None,
) -> list[str]:
    """Build fixed Docker argv for offline wheel installation."""

    active = policy or SandboxPolicy(image=plan.runner_image)
    _require_policy_image(plan, active)
    _require_docker_token(input_volume, "input volume")
    _require_docker_token(wheelhouse_volume, "wheelhouse volume")
    _require_docker_token(dependency_volume, "dependency volume")
    args = _base_create_args(active, name=name, run_id=run_id, network="none")
    args.extend(
        [
            "--mount",
            f"type=volume,src={input_volume},dst=/input,readonly",
            "--mount",
            f"type=volume,src={wheelhouse_volume},dst=/wheelhouse,readonly",
            "--mount",
            f"type=volume,src={dependency_volume},dst=/dependencies",
            "--workdir",
            "/tmp",  # noqa: S108 - path is inside the preparation container
            "--entrypoint",
            "/usr/bin/env",
            active.image,
            "-i",
            *_pip_environment(),
            "/usr/local/bin/python",
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-cache-dir",
            "--no-index",
            "--find-links=/wheelhouse",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "--no-compile",
            "--target",
            "/dependencies",
            "--requirement",
            "/input/requirements.lock",
        ]
    )
    return args


def attest_wheelhouse(root: Path, plan: DependencyPlan) -> WheelhouseAttestation:
    """Hash and minimally parse wheels without extracting or importing package code."""

    root_path = Path(root)
    try:
        root_stat = root_path.lstat()
    except OSError as exc:
        raise _rejection("Wheelhouse is unavailable.") from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        raise _rejection("Wheelhouse is not a real directory.")

    entries = sorted(root_path.iterdir(), key=lambda item: item.name)
    if not 1 <= len(entries) <= MAX_WHEELS:
        raise _rejection(f"Wheelhouse must contain 1-{MAX_WHEELS} wheels.")
    expected = {package.name: package for package in plan.packages}
    artifacts: list[WheelArtifact] = []
    seen_packages: set[str] = set()
    total_bytes = 0
    total_unpacked_bytes = 0
    for entry in entries:
        metadata = entry.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not entry.name.endswith(".whl")
            or not entry.name.isascii()
            or len(entry.name.encode("ascii")) > 255
        ):
            raise _rejection("Wheelhouse contains a non-regular or invalidly named artifact.")
        if not 1 <= metadata.st_size <= MAX_WHEEL_BYTES:
            raise _rejection("Wheel artifact exceeds the byte limit.")

        with open_regular_file(entry) as stream:
            opened = os.fstat(stream.fileno())
            if not _same_file_snapshot(metadata, opened):
                raise _rejection("Wheel artifact changed while it was opened.")
            total_bytes += opened.st_size
            if total_bytes > MAX_WHEELHOUSE_BYTES:
                raise _rejection("Wheelhouse exceeds the total byte limit.")
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                digest.update(chunk)
            stream.seek(0)
            package_name, version, unpacked_bytes = _read_wheel_identity(stream)
            if not _same_file_snapshot(opened, os.fstat(stream.fileno())):
                raise _rejection("Wheel artifact changed during attestation.")
        total_unpacked_bytes += unpacked_bytes
        if total_unpacked_bytes > MAX_WHEELHOUSE_UNPACKED_BYTES:
            raise _rejection("Wheelhouse declared unpacked bytes exceed the aggregate limit.")
        package = expected.get(package_name)
        artifact_sha256 = digest.hexdigest()
        if package is None or version != package.version or artifact_sha256 not in package.sha256:
            raise _rejection(
                "Wheel identity or digest is absent from the reviewed dependency plan."
            )
        if package_name in seen_packages:
            raise _rejection(f"Wheelhouse repeats package {package_name!r}.")
        seen_packages.add(package_name)
        artifacts.append(
            WheelArtifact(
                package=package_name,
                version=version,
                filename=entry.name,
                sha256=artifact_sha256,
                bytes=opened.st_size,
                unpacked_bytes=unpacked_bytes,
            )
        )
    if seen_packages != set(expected):
        raise _rejection("Wheelhouse does not contain exactly the reviewed dependency closure.")

    artifacts.sort(key=lambda item: item.package)
    canonical_files = [asdict(artifact) for artifact in artifacts]
    return WheelhouseAttestation(
        algorithm=WHEELHOUSE_ALGORITHM,
        sha256=hashlib.sha256(_canonical_json_bytes(canonical_files)).hexdigest(),
        file_count=len(artifacts),
        total_bytes=total_bytes,
        total_unpacked_bytes=total_unpacked_bytes,
        files=tuple(artifacts),
    )


def build_dependency_receipt(
    plan: DependencyPlan,
    *,
    runner_image_id: str,
    wheelhouse: WheelhouseAttestation,
    dependency_tree: SourceTreeAttestation,
    tool_git_sha: str,
    policy: SandboxPolicy | None = None,
) -> dict[str, object]:
    """Build deterministic preparation evidence without mutating a campaign."""

    image_id = _ascii_pattern(runner_image_id, "runner image ID", _IMAGE_ID)
    git_sha = _ascii_pattern(tool_git_sha, "tool Git SHA", _GIT_SHA)
    if dependency_tree.expected_git_tree_oid is not None:
        raise _rejection("Dependency tree attestation must not claim a Git source-tree binding.")
    if wheelhouse.algorithm != WHEELHOUSE_ALGORITHM:
        raise _rejection("Wheelhouse attestation algorithm is unsupported.")
    expected_packages = {package.name: package for package in plan.packages}
    actual_packages = {item.package: item for item in wheelhouse.files}
    if (
        set(expected_packages) != set(actual_packages)
        or len(actual_packages) != len(wheelhouse.files)
        or wheelhouse.file_count != len(wheelhouse.files)
        or wheelhouse.file_count > MAX_WHEELS
    ):
        raise _rejection("Wheelhouse receipt does not match the dependency plan.")
    if tuple(wheelhouse.files) != tuple(sorted(wheelhouse.files, key=lambda item: item.package)):
        raise _rejection("Wheelhouse receipt files are not canonically ordered.")
    for package_name, item in actual_packages.items():
        package = expected_packages[package_name]
        if (
            item.version != package.version
            or item.sha256 not in package.sha256
            or _WHEEL_FILENAME.fullmatch(item.filename) is None
            or not 1 <= item.bytes <= MAX_WHEEL_BYTES
            or not 1 <= item.unpacked_bytes <= MAX_WHEEL_UNPACKED_BYTES
        ):
            raise _rejection("Wheelhouse receipt contains unreviewed artifact evidence.")
    if (
        wheelhouse.total_bytes != sum(item.bytes for item in wheelhouse.files)
        or not 1 <= wheelhouse.total_bytes <= MAX_WHEELHOUSE_BYTES
        or wheelhouse.total_unpacked_bytes != sum(item.unpacked_bytes for item in wheelhouse.files)
        or not 1 <= wheelhouse.total_unpacked_bytes <= MAX_WHEELHOUSE_UNPACKED_BYTES
    ):
        raise _rejection("Wheelhouse receipt byte count is inconsistent.")
    canonical_files = [asdict(item) for item in wheelhouse.files]
    expected_wheelhouse_sha = hashlib.sha256(_canonical_json_bytes(canonical_files)).hexdigest()
    if wheelhouse.sha256 != expected_wheelhouse_sha:
        raise _rejection("Wheelhouse receipt digest is inconsistent.")
    if (
        dependency_tree.algorithm != SOURCE_TREE_ALGORITHM
        or not dependency_tree.git_metadata_absent
        or dependency_tree.member_count
        != dependency_tree.file_count + dependency_tree.directory_count
        or any(
            value < 0
            for value in (
                dependency_tree.member_count,
                dependency_tree.file_count,
                dependency_tree.directory_count,
                dependency_tree.total_bytes,
                dependency_tree.executable_count,
            )
        )
        or dependency_tree.executable_count > dependency_tree.file_count
    ):
        raise _rejection("Dependency tree attestation is inconsistent.")

    active = policy or SandboxPolicy(image=plan.runner_image)
    _require_policy_image(plan, active)
    policy_record = dependency_preparation_policy(active)
    policy_sha256 = hashlib.sha256(_canonical_json_bytes(policy_record)).hexdigest()
    identity = {
        "algorithm": EVALUATOR_PACKAGE_ALGORITHM,
        "runner_image_id": image_id,
        "plan_sha256": plan.canonical_sha256,
        "policy_sha256": policy_sha256,
        "wheelhouse_sha256": wheelhouse.sha256,
        "dependency_tree_sha256": dependency_tree.tree_sha256,
        "python_version": plan.python_version,
    }
    package_sha256 = hashlib.sha256(_canonical_json_bytes(identity)).hexdigest()

    return {
        "schema_version": DEPENDENCY_RECEIPT_SCHEMA_VERSION,
        "case": {
            "id": plan.case_id,
            "base_sha": plan.base_sha,
            "source_tree_sha256": plan.source_tree_sha256,
        },
        "plan": {
            "raw_sha256": plan.raw_sha256,
            "canonical_sha256": plan.canonical_sha256,
            "requirements_sha256": hashlib.sha256(render_requirements_lock(plan)).hexdigest(),
            "package_count": len(plan.packages),
        },
        "preparation": {
            "policy": policy_record,
            "policy_sha256": policy_sha256,
            "network_phase": "trusted_pip_wheel_download_only",
            "install_network": "none",
            "source_mounted_during_network_phase": False,
            "host_credentials_forwarded": False,
        },
        "runner": {
            "image": plan.runner_image,
            "image_id": image_id,
            "python_version": plan.python_version,
        },
        "wheelhouse": {
            "algorithm": wheelhouse.algorithm,
            "sha256": wheelhouse.sha256,
            "file_count": wheelhouse.file_count,
            "total_bytes": wheelhouse.total_bytes,
            "total_unpacked_bytes": wheelhouse.total_unpacked_bytes,
            "files": canonical_files,
        },
        "dependencies": {
            "attestation": {
                "algorithm": dependency_tree.algorithm,
                "tree_sha256": dependency_tree.tree_sha256,
                "member_count": dependency_tree.member_count,
                "file_count": dependency_tree.file_count,
                "directory_count": dependency_tree.directory_count,
                "total_bytes": dependency_tree.total_bytes,
                "executable_count": dependency_tree.executable_count,
                "links_and_special_files_absent": True,
            }
        },
        "evaluator_package": {
            "algorithm": EVALUATOR_PACKAGE_ALGORITHM,
            "sha256": package_sha256,
            "identity": identity,
            "artifact_kind": "controller_owned_dependency_volume",
            "verification_mount": "read_only_at_/dependencies",
            "verification_network": "none",
        },
        "tool": {"name": "reproassert", "version": __version__, "git_sha": git_sha},
        "campaign_readiness_changed": False,
        "limitations": [
            "Docker bridge egress is constrained by trusted pip argv, not a network-layer ACL.",
            "This wheel-only profile rejects sdists, VCS dependencies, and repository build steps.",
            (
                "The package digest binds the runner image ID and read-only dependency tree; "
                "it is not an OCI image digest or signature."
            ),
        ],
    }


def canonical_receipt_bytes(receipt: Mapping[str, object]) -> bytes:
    return _canonical_json_bytes(receipt) + b"\n"


def _base_create_args(policy: SandboxPolicy, *, name: str, run_id: str, network: str) -> list[str]:
    _require_docker_token(name, "container name")
    _require_docker_token(run_id, "run ID")
    return [
        "create",
        "--name",
        name,
        "--label",
        f"io.reproassert.run={run_id}",
        "--label",
        "io.reproassert.owner=controller-v1",
        "--pull",
        "never",
        "--network",
        network,
        "--read-only",
        "--user",
        "65532:65532",
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
        f"fsize={MAX_WHEEL_BYTES}:{MAX_WHEEL_BYTES}",
        "--shm-size",
        "64m",
        "--init",
        "--tmpfs",
        (
            f"/tmp:rw,noexec,nosuid,nodev,size={policy.tmpfs_bytes},"  # noqa: S108 - container tmpfs
            f"nr_inodes={policy.tmpfs_inodes}"
        ),
        "--log-driver",
        "local",
        "--log-opt",
        "max-size=128k",
        "--log-opt",
        "max-file=1",
        "--log-opt",
        "compress=false",
    ]


def _pip_environment() -> list[str]:
    return [
        "HOME=/tmp/home",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "PIP_CONFIG_FILE=/dev/null",
        "PIP_DISABLE_PIP_VERSION_CHECK=1",
        "PIP_NO_INPUT=1",
        "PIP_NO_PYTHON_VERSION_WARNING=1",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONHASHSEED=0",
        "TZ=UTC",
    ]


def _read_wheel_identity(stream: Any) -> tuple[str, str, int]:
    try:
        with zipfile.ZipFile(stream) as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= MAX_WHEEL_MEMBERS:
                raise _rejection("Wheel member count is outside the policy limit.")
            seen_paths: set[str] = set()
            metadata_members: list[zipfile.ZipInfo] = []
            total_unpacked = 0
            for info in infos:
                _validate_wheel_member(info, seen_paths)
                total_unpacked += info.file_size
                if total_unpacked > MAX_WHEEL_UNPACKED_BYTES:
                    raise _rejection("Wheel declared unpacked bytes exceed the policy limit.")
                if info.filename.endswith(".dist-info/METADATA"):
                    metadata_members.append(info)
            if len(metadata_members) != 1:
                raise _rejection("Wheel must contain exactly one dist-info METADATA file.")
            metadata_info = metadata_members[0]
            if metadata_info.file_size > MAX_METADATA_BYTES:
                raise _rejection("Wheel METADATA exceeds the byte limit.")
            with archive.open(metadata_info) as metadata_stream:
                metadata_bytes = metadata_stream.read(MAX_METADATA_BYTES + 1)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise _rejection("Wheel is not a readable bounded ZIP artifact.") from exc
    if len(metadata_bytes) > MAX_METADATA_BYTES:
        raise _rejection("Wheel METADATA exceeds the byte limit.")
    message = BytesParser(policy=compat32).parsebytes(metadata_bytes)
    names = message.get_all("Name", [])
    versions = message.get_all("Version", [])
    if len(names) != 1 or len(versions) != 1:
        raise _rejection("Wheel METADATA must contain exactly one Name and Version.")
    name = _normalize_package_name(str(names[0]))
    version = _ascii_pattern(str(versions[0]), "wheel version", _VERSION)
    return name, version, total_unpacked


def _validate_wheel_member(info: zipfile.ZipInfo, seen_paths: set[str]) -> None:
    name = info.filename
    if not name or "\\" in name or any(ord(character) < 32 for character in name):
        raise _rejection("Wheel contains an invalid member path.")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise _rejection("Wheel contains an unsafe member path.")
    if name in seen_paths:
        raise _rejection("Wheel contains a duplicate member path.")
    seen_paths.add(name)
    if info.flag_bits & 0x1:
        raise _rejection("Encrypted wheel members are unsupported.")
    file_type = stat.S_IFMT((info.external_attr >> 16) & 0xFFFF)
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise _rejection("Wheel contains a link or special filesystem member.")
    if info.file_size < 0 or info.file_size > MAX_WHEEL_UNPACKED_BYTES:
        raise _rejection("Wheel member exceeds the byte limit.")


def _normalize_package_name(value: str) -> str:
    if not value.isascii() or not value:
        raise _rejection("Wheel package name is invalid.")
    normalized = re.sub(r"[-_.]+", "-", value).lower()
    return _ascii_pattern(normalized, "wheel package name", _PACKAGE_NAME)


def _require_policy_image(plan: DependencyPlan, policy: SandboxPolicy) -> None:
    if policy.image != plan.runner_image:
        raise _rejection("Sandbox policy image does not match the dependency plan.")


def _require_docker_token(value: str, label: str) -> None:
    if not isinstance(value, str) or _DOCKER_TOKEN.fullmatch(value) is None:
        raise _rejection(f"{label.capitalize()} is not a safe Docker token.")


def _same_file_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISREG(right.st_mode)
        and right.st_nlink == 1
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_mode == right.st_mode
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _read_bounded_regular(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            value = stream.read(limit + 1)
    except OSError as exc:
        raise _rejection(f"Unable to read {label}.") from exc
    if len(value) > limit:
        raise _rejection(f"{label.capitalize()} exceeds the byte limit.")
    return value


def _decode_strict_json(raw: bytes, label: str) -> object:
    def reject_duplicates(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise _rejection(f"{label.capitalize()} contains duplicate object keys.")
            result[key] = value
        return result

    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
        _check_json_nesting(decoded)
        return decoded
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _rejection(f"{label.capitalize()} is not valid bounded UTF-8 JSON.") from exc


def _check_json_nesting(value: object, *, depth: int = 0) -> None:
    if depth > MAX_JSON_NESTING:
        raise _rejection("JSON nesting exceeds the policy limit.")
    if isinstance(value, dict):
        for child in value.values():
            _check_json_nesting(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _check_json_nesting(child, depth=depth + 1)


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _rejection(f"{label.capitalize()} fields are incomplete or unexpected.")
    return value


def _ascii_pattern(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not value.isascii() or pattern.fullmatch(value) is None:
        raise _rejection(f"{label.capitalize()} is invalid.")
    return value


def _require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise _rejection(f"{label.capitalize()} does not match the frozen contract.")


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
        raise _rejection("Value cannot be represented as canonical JSON.") from exc


def _rejection(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_dependency_prep", message)
