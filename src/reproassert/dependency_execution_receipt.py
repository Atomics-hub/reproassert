from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, cast

from reproassert.dependency_command_contract import (
    DependencyPhase,
    dependency_phase_command_sha256,
)
from reproassert.dependency_executor import (
    DEPENDENCY_CAUSALITY_ALGORITHM,
    DEPENDENCY_EXECUTION_SCHEMA_VERSION,
    DEPENDENCY_VOLUME_QUOTA_CONTRACT,
    MAX_EXECUTION_RECEIPT_BYTES,
    OWNER_LABEL_KEY,
    PLAN_LABEL_KEY,
    ROLE_LABEL_KEY,
    RUN_LABEL_KEY,
    ExecutionState,
)
from reproassert.dependency_prep import (
    DEPENDENCY_POLICY_ID,
    DEPENDENCY_RECEIPT_SCHEMA_VERSION,
    EVALUATOR_PACKAGE_ALGORITHM,
    MAX_PACKAGES,
    MAX_WHEEL_BYTES,
    MAX_WHEEL_UNPACKED_BYTES,
    MAX_WHEELHOUSE_BYTES,
    MAX_WHEELHOUSE_UNPACKED_BYTES,
    MAX_WHEELS,
    WHEELHOUSE_ALGORITHM,
    DependencyPlan,
    dependency_preparation_policy,
    load_dependency_plan,
    render_requirements_lock,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file
from reproassert.sandbox import SandboxPolicy
from reproassert.source_attestation import SOURCE_TREE_ALGORITHM

DEPENDENCY_EXECUTION_RECEIPT_SCHEMA_FILENAME = "dependency-execution-receipt.schema.json"
MAX_JSON_NESTING = 64

_CASE_ID = re.compile(r"rk-v(?:0\.1|0\.2)-[0-9]{3}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_IMAGE_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,199}")
_PYTHON_VERSION = re.compile(r"3\.[0-9]{1,2}(?:\.[0-9]{1,2})?")
_PACKAGE_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}")
_TOOL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
_TOOL_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}")
_WHEEL_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,249}\.whl")
_EPHEMERAL_RESOURCE = re.compile(r"reproassert-dep-[A-Za-z0-9_.-]+")

_ROOT_KEYS = {
    "schema_version",
    "kind",
    "dependency_preparation",
    "execution",
    "campaign_readiness_changed",
}
_PREPARATION_ROOT_KEYS = {
    "schema_version",
    "case",
    "plan",
    "preparation",
    "runner",
    "wheelhouse",
    "dependencies",
    "evaluator_package",
    "tool",
    "campaign_readiness_changed",
    "limitations",
}
_CASE_KEYS = {"id", "base_sha", "source_tree_sha256"}
_PLAN_KEYS = {"raw_sha256", "canonical_sha256", "requirements_sha256", "package_count"}
_PREPARATION_KEYS = {
    "policy",
    "policy_sha256",
    "network_phase",
    "install_network",
    "source_mounted_during_network_phase",
    "host_credentials_forwarded",
}
_RUNNER_KEYS = {"image", "image_id", "python_version"}
_WHEELHOUSE_KEYS = {
    "algorithm",
    "sha256",
    "file_count",
    "total_bytes",
    "total_unpacked_bytes",
    "files",
}
_WHEEL_KEYS = {"package", "version", "filename", "sha256", "bytes", "unpacked_bytes"}
_DEPENDENCIES_KEYS = {"attestation"}
_TREE_KEYS = {
    "algorithm",
    "tree_sha256",
    "member_count",
    "file_count",
    "directory_count",
    "total_bytes",
    "executable_count",
    "links_and_special_files_absent",
}
_EVALUATOR_KEYS = {
    "algorithm",
    "sha256",
    "identity",
    "artifact_kind",
    "verification_mount",
    "verification_network",
}
_IDENTITY_KEYS = {
    "algorithm",
    "runner_image_id",
    "plan_sha256",
    "policy_sha256",
    "wheelhouse_sha256",
    "dependency_tree_sha256",
    "python_version",
}
_TOOL_KEYS = {"name", "version", "git_sha"}
_EXECUTION_KEYS = {
    "algorithm",
    "runner",
    "volume_policy",
    "download",
    "install",
    "causality",
    "cleanup",
}
_EXECUTION_RUNNER_KEYS = {
    "image_id",
    "python_version",
    "image_resolved_once_before_resource_creation",
}
_VOLUME_POLICY_KEYS = {
    "driver",
    "type",
    "read_only_retention_anchor",
    "size_bytes",
    "max_inodes",
    "uid",
    "gid",
    "mode",
    "labels",
}
_PHASE_KEYS = {
    "phase",
    "image_id",
    "network_mode",
    "user",
    "read_only_root",
    "cap_drop",
    "no_new_privileges",
    "healthcheck_disabled",
    "trusted_phase_command",
    "pids",
    "memory_bytes",
    "memory_swap_bytes",
    "nano_cpus",
    "mounts",
    "command_sha256",
    "config_sha256",
    "outcome",
}
_OUTCOME_KEYS = {"phase", "exit_code", "oom_killed", "timed_out", "output_truncated"}
_CAUSALITY_KEYS = {
    "events",
    "sequence_sha256",
    "volumes_new_and_empty",
    "download_precedes_wheelhouse_attestation",
    "install_precedes_dependency_attestation",
    "wheelhouse_unchanged_across_install",
    "requirements_unchanged",
    "dependency_volume_rw_phase_count",
    "download_source_mounted",
    "install_network",
}
_CLEANUP_KEYS = {
    "input_volume_removed",
    "wheelhouse_volume_removed",
    "dependency_volume_retained_inside_executor_context",
    "label_verification_required",
    "blind_force_volume_removal",
}

_LIMITATIONS = [
    "Docker bridge egress is constrained by trusted pip argv, not a network-layer ACL.",
    "This wheel-only profile rejects sdists, VCS dependencies, and repository build steps.",
    (
        "The package digest binds the runner image ID and read-only dependency tree; "
        "it is not an OCI image digest or signature."
    ),
]
_LABEL_KEYS = [OWNER_LABEL_KEY, RUN_LABEL_KEY, ROLE_LABEL_KEY, PLAN_LABEL_KEY]
_EMPTY_PROBE_SHA256 = hashlib.sha256(b"reproassert-volume-probe-v1\0").hexdigest()


@dataclass(frozen=True)
class VerifiedDependencyExecutionReceipt:
    receipt_sha256: str
    case_id: str
    base_sha: str
    source_tree_sha256: str
    plan_raw_sha256: str
    plan_sha256: str
    requirements_sha256: str
    image_id: str
    policy_sha256: str
    wheelhouse_sha256: str
    dependency_tree_sha256: str
    evaluator_package_sha256: str
    sequence_sha256: str
    tool_name: str
    tool_version: str
    tool_git_sha: str
    campaign_readiness_changed: bool = False


@dataclass(frozen=True)
class _PreparationEvidence:
    case_id: str
    base_sha: str
    source_tree_sha256: str
    plan_raw_sha256: str
    plan_sha256: str
    requirements_sha256: str
    image: str
    image_id: str
    python_version: str
    policy: SandboxPolicy
    policy_sha256: str
    wheelhouse_sha256: str
    dependency_tree_sha256: str
    evaluator_package_sha256: str
    tool_name: str
    tool_version: str
    tool_git_sha: str


def dependency_execution_receipt_schema_text() -> str:
    """Return the exact dependency execution schema shipped in the installed package."""

    return (
        resources.files("reproassert")
        .joinpath("schemas")
        .joinpath(DEPENDENCY_EXECUTION_RECEIPT_SCHEMA_FILENAME)
        .read_text(encoding="utf-8")
    )


def load_dependency_execution_receipt(
    path: Path,
    *,
    expected_receipt_sha256: str | None = None,
    expected_plan_path: Path | None = None,
    expected_case_id: str | None = None,
    expected_base_sha: str | None = None,
    expected_source_tree_sha256: str | None = None,
    expected_plan_raw_sha256: str | None = None,
    expected_plan_sha256: str | None = None,
    expected_image_id: str | None = None,
    expected_tool_name: str | None = None,
    expected_tool_version: str | None = None,
    expected_tool_git_sha: str | None = None,
) -> VerifiedDependencyExecutionReceipt:
    """Load and independently verify one canonical causal dependency receipt."""

    raw = _read_bounded_regular(path)
    actual_receipt_sha256 = hashlib.sha256(raw).hexdigest()
    _bind_expected(
        actual_receipt_sha256,
        expected_receipt_sha256,
        "receipt SHA-256",
        _SHA256,
    )
    decoded = _decode_strict_json(raw)
    canonical = _canonical_json_bytes(decoded) + b"\n"
    if raw != canonical:
        raise _reject("Dependency execution receipt is not canonical JSON with one final newline.")
    return verify_dependency_execution_receipt(
        _object(decoded, "receipt"),
        expected_plan_path=expected_plan_path,
        expected_case_id=expected_case_id,
        expected_base_sha=expected_base_sha,
        expected_source_tree_sha256=expected_source_tree_sha256,
        expected_plan_raw_sha256=expected_plan_raw_sha256,
        expected_plan_sha256=expected_plan_sha256,
        expected_image_id=expected_image_id,
        expected_tool_name=expected_tool_name,
        expected_tool_version=expected_tool_version,
        expected_tool_git_sha=expected_tool_git_sha,
    )


def verify_dependency_execution_receipt(
    receipt: Mapping[str, object],
    *,
    expected_plan_path: Path | None = None,
    expected_case_id: str | None = None,
    expected_base_sha: str | None = None,
    expected_source_tree_sha256: str | None = None,
    expected_plan_raw_sha256: str | None = None,
    expected_plan_sha256: str | None = None,
    expected_image_id: str | None = None,
    expected_tool_name: str | None = None,
    expected_tool_version: str | None = None,
    expected_tool_git_sha: str | None = None,
) -> VerifiedDependencyExecutionReceipt:
    """Recompute all receipt identities available from the self-contained evidence."""

    trusted_plan = (
        load_dependency_plan(expected_plan_path) if expected_plan_path is not None else None
    )
    root = _exact_object(receipt, _ROOT_KEYS, "receipt")
    _reject_ephemeral_resource_names(root)
    _equal(root.get("schema_version"), DEPENDENCY_EXECUTION_SCHEMA_VERSION, "schema version")
    _equal(root.get("kind"), "dependency_execution_receipt", "receipt kind")
    _false(root.get("campaign_readiness_changed"), "campaign readiness")
    preparation = _validate_preparation(
        root.get("dependency_preparation"),
        trusted_plan=trusted_plan,
    )
    sequence_sha256 = _validate_execution(root.get("execution"), preparation)

    _bind_expected(preparation.case_id, expected_case_id, "case ID", _CASE_ID)
    _bind_expected(preparation.base_sha, expected_base_sha, "base SHA", _GIT_SHA)
    _bind_expected(
        preparation.source_tree_sha256,
        expected_source_tree_sha256,
        "source tree SHA-256",
        _SHA256,
    )
    _bind_expected(
        preparation.plan_raw_sha256,
        expected_plan_raw_sha256,
        "plan raw SHA-256",
        _SHA256,
    )
    _bind_expected(
        preparation.plan_sha256,
        expected_plan_sha256,
        "plan canonical SHA-256",
        _SHA256,
    )
    _bind_expected(preparation.image_id, expected_image_id, "runner image ID", _IMAGE_ID)
    _bind_expected(preparation.tool_name, expected_tool_name, "tool name", _TOOL_NAME)
    _bind_expected(
        preparation.tool_version,
        expected_tool_version,
        "tool version",
        _TOOL_VERSION,
    )
    _bind_expected(
        preparation.tool_git_sha,
        expected_tool_git_sha,
        "tool Git SHA",
        _GIT_SHA,
    )
    receipt_sha256 = hashlib.sha256(_canonical_json_bytes(root) + b"\n").hexdigest()
    return VerifiedDependencyExecutionReceipt(
        receipt_sha256=receipt_sha256,
        case_id=preparation.case_id,
        base_sha=preparation.base_sha,
        source_tree_sha256=preparation.source_tree_sha256,
        plan_raw_sha256=preparation.plan_raw_sha256,
        plan_sha256=preparation.plan_sha256,
        requirements_sha256=preparation.requirements_sha256,
        image_id=preparation.image_id,
        policy_sha256=preparation.policy_sha256,
        wheelhouse_sha256=preparation.wheelhouse_sha256,
        dependency_tree_sha256=preparation.dependency_tree_sha256,
        evaluator_package_sha256=preparation.evaluator_package_sha256,
        sequence_sha256=sequence_sha256,
        tool_name=preparation.tool_name,
        tool_version=preparation.tool_version,
        tool_git_sha=preparation.tool_git_sha,
    )


def _validate_preparation(
    value: object,
    *,
    trusted_plan: DependencyPlan | None,
) -> _PreparationEvidence:
    root = _exact_object(value, _PREPARATION_ROOT_KEYS, "dependency preparation")
    _equal(root.get("schema_version"), DEPENDENCY_RECEIPT_SCHEMA_VERSION, "preparation schema")
    _false(root.get("campaign_readiness_changed"), "preparation campaign readiness")
    limitations = _list(root.get("limitations"), "preparation limitations")
    if limitations != _LIMITATIONS:
        raise _reject("Dependency preparation limitations changed.")

    case = _exact_object(root.get("case"), _CASE_KEYS, "preparation case")
    case_id = _pattern(case.get("id"), "case ID", _CASE_ID)
    base_sha = _pattern(case.get("base_sha"), "base SHA", _GIT_SHA)
    source_tree_sha256 = _pattern(case.get("source_tree_sha256"), "source tree SHA-256", _SHA256)

    plan = _exact_object(root.get("plan"), _PLAN_KEYS, "preparation plan")
    plan_raw_sha256 = _pattern(plan.get("raw_sha256"), "plan raw SHA-256", _SHA256)
    plan_sha256 = _pattern(plan.get("canonical_sha256"), "plan canonical SHA-256", _SHA256)
    requirements_sha256 = _pattern(plan.get("requirements_sha256"), "requirements SHA-256", _SHA256)
    package_count = _integer(plan.get("package_count"), "plan package count", minimum=1)
    if package_count > MAX_PACKAGES:
        raise _reject("Plan package count exceeds the policy bound.")
    if trusted_plan is not None:
        receipt_plan = {
            "case_id": case_id,
            "base_sha": base_sha,
            "source_tree_sha256": source_tree_sha256,
            "raw_sha256": plan_raw_sha256,
            "canonical_sha256": plan_sha256,
            "requirements_sha256": requirements_sha256,
            "package_count": package_count,
        }
        strict_plan = {
            "case_id": trusted_plan.case_id,
            "base_sha": trusted_plan.base_sha,
            "source_tree_sha256": trusted_plan.source_tree_sha256,
            "raw_sha256": trusted_plan.raw_sha256,
            "canonical_sha256": trusted_plan.canonical_sha256,
            "requirements_sha256": hashlib.sha256(
                render_requirements_lock(trusted_plan)
            ).hexdigest(),
            "package_count": len(trusted_plan.packages),
        }
        if receipt_plan != strict_plan:
            raise _reject("Strict dependency plan does not match the execution receipt.")

    runner = _exact_object(root.get("runner"), _RUNNER_KEYS, "preparation runner")
    image = _pattern(runner.get("image"), "runner image", _IMAGE_REFERENCE)
    image_id = _pattern(runner.get("image_id"), "runner image ID", _IMAGE_ID)
    python_version = _pattern(
        runner.get("python_version"), "runner Python version", _PYTHON_VERSION
    )
    if trusted_plan is not None and (
        image != trusted_plan.runner_image or python_version != trusted_plan.python_version
    ):
        raise _reject("Strict dependency plan runtime does not match the execution receipt.")

    preparation = _exact_object(
        root.get("preparation"), _PREPARATION_KEYS, "preparation policy record"
    )
    policy, policy_sha256 = _validate_policy(
        preparation.get("policy"),
        preparation.get("policy_sha256"),
        image=image,
    )
    _equal(
        preparation.get("network_phase"),
        "trusted_pip_wheel_download_only",
        "preparation network phase",
    )
    _equal(preparation.get("install_network"), "none", "preparation install network")
    _false(
        preparation.get("source_mounted_during_network_phase"),
        "preparation source mount",
    )
    _false(
        preparation.get("host_credentials_forwarded"),
        "preparation credential forwarding",
    )

    wheelhouse_sha256 = _validate_wheelhouse(
        root.get("wheelhouse"),
        package_count,
        trusted_plan=trusted_plan,
    )
    dependency_tree_sha256 = _validate_dependency_tree(root.get("dependencies"))
    evaluator_package_sha256 = _validate_evaluator_package(
        root.get("evaluator_package"),
        image_id=image_id,
        plan_sha256=plan_sha256,
        policy_sha256=policy_sha256,
        wheelhouse_sha256=wheelhouse_sha256,
        dependency_tree_sha256=dependency_tree_sha256,
        python_version=python_version,
    )

    tool = _exact_object(root.get("tool"), _TOOL_KEYS, "preparation tool")
    tool_name = _pattern(tool.get("name"), "tool name", _TOOL_NAME)
    tool_version = _pattern(tool.get("version"), "tool version", _TOOL_VERSION)
    tool_git_sha = _pattern(tool.get("git_sha"), "tool Git SHA", _GIT_SHA)
    return _PreparationEvidence(
        case_id=case_id,
        base_sha=base_sha,
        source_tree_sha256=source_tree_sha256,
        plan_raw_sha256=plan_raw_sha256,
        plan_sha256=plan_sha256,
        requirements_sha256=requirements_sha256,
        image=image,
        image_id=image_id,
        python_version=python_version,
        policy=policy,
        policy_sha256=policy_sha256,
        wheelhouse_sha256=wheelhouse_sha256,
        dependency_tree_sha256=dependency_tree_sha256,
        evaluator_package_sha256=evaluator_package_sha256,
        tool_name=tool_name,
        tool_version=tool_version,
        tool_git_sha=tool_git_sha,
    )


def _validate_policy(
    policy_value: object,
    policy_sha_value: object,
    *,
    image: str,
) -> tuple[SandboxPolicy, str]:
    policy = _object(policy_value, "dependency policy")
    container = _exact_object(
        policy.get("container"),
        {
            "image",
            "read_only_root",
            "user",
            "capabilities",
            "no_new_privileges",
            "host_bind_mounts",
            "docker_socket",
            "environment",
            "pids",
            "memory_bytes",
            "cpus",
            "tmpfs_bytes",
            "tmpfs_inodes",
            "timeout_seconds",
            "max_output_bytes",
        },
        "dependency container policy",
    )
    _equal(container.get("image"), image, "policy image")
    try:
        active = SandboxPolicy(
            image=image,
            timeout_seconds=_number(container.get("timeout_seconds"), "policy timeout"),
            max_output_bytes=_integer(
                container.get("max_output_bytes"), "policy output bytes", minimum=1
            ),
            memory_bytes=_integer(container.get("memory_bytes"), "policy memory bytes", minimum=1),
            cpus=_number(container.get("cpus"), "policy CPUs"),
            pids=_integer(container.get("pids"), "policy PIDs", minimum=1),
            tmpfs_bytes=_integer(container.get("tmpfs_bytes"), "policy tmpfs bytes", minimum=1),
            tmpfs_inodes=_integer(container.get("tmpfs_inodes"), "policy tmpfs inodes", minimum=1),
        )
    except ValueError as exc:
        raise _reject("Dependency container policy bounds are invalid.") from exc
    expected_policy = dependency_preparation_policy(active)
    if policy != expected_policy or policy.get("id") != DEPENDENCY_POLICY_ID:
        raise _reject("Dependency preparation policy does not match the executable contract.")
    policy_sha256 = _pattern(policy_sha_value, "dependency policy SHA-256", _SHA256)
    expected_sha256 = hashlib.sha256(_canonical_json_bytes(expected_policy)).hexdigest()
    _equal(policy_sha256, expected_sha256, "dependency policy SHA-256")
    return active, policy_sha256


def _validate_wheelhouse(
    value: object,
    package_count: int,
    *,
    trusted_plan: DependencyPlan | None,
) -> str:
    wheelhouse = _exact_object(value, _WHEELHOUSE_KEYS, "wheelhouse")
    _equal(wheelhouse.get("algorithm"), WHEELHOUSE_ALGORITHM, "wheelhouse algorithm")
    files = _list(wheelhouse.get("files"), "wheelhouse files")
    if not 1 <= len(files) <= MAX_WHEELS:
        raise _reject("Wheelhouse file count is outside the policy bound.")
    canonical_files: list[dict[str, object]] = []
    packages: list[str] = []
    filenames: set[str] = set()
    total_bytes = 0
    total_unpacked = 0
    for index, raw in enumerate(files, start=1):
        item = _exact_object(raw, _WHEEL_KEYS, f"wheelhouse file {index}")
        package = _pattern(item.get("package"), "wheel package", _PACKAGE_NAME)
        _pattern(item.get("version"), "wheel version", _VERSION)
        filename = _pattern(item.get("filename"), "wheel filename", _WHEEL_FILENAME)
        _pattern(item.get("sha256"), "wheel SHA-256", _SHA256)
        size = _integer(item.get("bytes"), "wheel bytes", minimum=1)
        unpacked = _integer(item.get("unpacked_bytes"), "wheel unpacked bytes", minimum=1)
        if size > MAX_WHEEL_BYTES or unpacked > MAX_WHEEL_UNPACKED_BYTES:
            raise _reject("Wheel artifact exceeds the policy bound.")
        if filename in filenames:
            raise _reject("Wheelhouse repeats an artifact filename.")
        filenames.add(filename)
        packages.append(package)
        total_bytes += size
        total_unpacked += unpacked
        canonical_files.append(dict(item))
    if packages != sorted(set(packages)) or len(packages) != package_count:
        raise _reject("Wheelhouse packages are not the exact canonical dependency closure.")
    if trusted_plan is not None:
        expected_packages = {package.name: package for package in trusted_plan.packages}
        for item in canonical_files:
            package_name = cast(str, item["package"])
            expected_package = expected_packages.get(package_name)
            if (
                expected_package is None
                or item["version"] != expected_package.version
                or item["sha256"] not in expected_package.sha256
            ):
                raise _reject("Wheelhouse artifact is absent from the strict dependency plan.")
        if set(packages) != set(expected_packages):
            raise _reject("Wheelhouse does not match the strict dependency closure.")
    if total_bytes > MAX_WHEELHOUSE_BYTES or total_unpacked > MAX_WHEELHOUSE_UNPACKED_BYTES:
        raise _reject("Wheelhouse aggregate bytes exceed the policy bound.")
    _equal(wheelhouse.get("file_count"), len(files), "wheelhouse file count")
    _equal(wheelhouse.get("total_bytes"), total_bytes, "wheelhouse total bytes")
    _equal(
        wheelhouse.get("total_unpacked_bytes"),
        total_unpacked,
        "wheelhouse total unpacked bytes",
    )
    wheelhouse_sha256 = _pattern(wheelhouse.get("sha256"), "wheelhouse SHA-256", _SHA256)
    expected_sha256 = hashlib.sha256(_canonical_json_bytes(canonical_files)).hexdigest()
    _equal(wheelhouse_sha256, expected_sha256, "wheelhouse SHA-256")
    return wheelhouse_sha256


def _validate_dependency_tree(value: object) -> str:
    dependencies = _exact_object(value, _DEPENDENCIES_KEYS, "dependencies")
    tree = _exact_object(dependencies.get("attestation"), _TREE_KEYS, "dependency tree")
    _equal(tree.get("algorithm"), SOURCE_TREE_ALGORITHM, "dependency tree algorithm")
    tree_sha256 = _pattern(tree.get("tree_sha256"), "dependency tree SHA-256", _SHA256)
    member_count = _integer(tree.get("member_count"), "tree member count", minimum=1)
    file_count = _integer(tree.get("file_count"), "tree file count", minimum=1)
    directory_count = _integer(tree.get("directory_count"), "tree directory count", minimum=0)
    total_bytes = _integer(tree.get("total_bytes"), "tree total bytes", minimum=0)
    executable_count = _integer(tree.get("executable_count"), "tree executable count", minimum=0)
    if (
        member_count != file_count + directory_count
        or executable_count > file_count
        or member_count > 20_000
        or file_count > 20_000
        or directory_count > 20_000
        or total_bytes > MAX_WHEELHOUSE_UNPACKED_BYTES
    ):
        raise _reject("Dependency tree attestation counts are inconsistent.")
    _true(
        tree.get("links_and_special_files_absent"),
        "dependency links and special files",
    )
    return tree_sha256


def _validate_evaluator_package(
    value: object,
    *,
    image_id: str,
    plan_sha256: str,
    policy_sha256: str,
    wheelhouse_sha256: str,
    dependency_tree_sha256: str,
    python_version: str,
) -> str:
    package = _exact_object(value, _EVALUATOR_KEYS, "evaluator package")
    identity = {
        "algorithm": EVALUATOR_PACKAGE_ALGORITHM,
        "runner_image_id": image_id,
        "plan_sha256": plan_sha256,
        "policy_sha256": policy_sha256,
        "wheelhouse_sha256": wheelhouse_sha256,
        "dependency_tree_sha256": dependency_tree_sha256,
        "python_version": python_version,
    }
    _equal(package.get("algorithm"), EVALUATOR_PACKAGE_ALGORITHM, "package algorithm")
    observed_identity = _exact_object(
        package.get("identity"), _IDENTITY_KEYS, "evaluator package identity"
    )
    if observed_identity != identity:
        raise _reject("Evaluator package identity does not match its dependency evidence.")
    package_sha256 = _pattern(package.get("sha256"), "evaluator package SHA-256", _SHA256)
    expected_sha256 = hashlib.sha256(_canonical_json_bytes(identity)).hexdigest()
    _equal(package_sha256, expected_sha256, "evaluator package SHA-256")
    _equal(
        package.get("artifact_kind"),
        "controller_owned_dependency_volume",
        "evaluator artifact kind",
    )
    _equal(
        package.get("verification_mount"),
        "read_only_at_/dependencies",
        "evaluator verification mount",
    )
    _equal(package.get("verification_network"), "none", "evaluator verification network")
    return package_sha256


def _validate_execution(value: object, preparation: _PreparationEvidence) -> str:
    execution = _exact_object(value, _EXECUTION_KEYS, "dependency execution")
    _equal(execution.get("algorithm"), DEPENDENCY_CAUSALITY_ALGORITHM, "causality algorithm")
    runner = _exact_object(execution.get("runner"), _EXECUTION_RUNNER_KEYS, "execution runner")
    _equal(runner.get("image_id"), preparation.image_id, "execution image ID")
    observed_python = _pattern(
        runner.get("python_version"), "execution Python version", _PYTHON_VERSION
    )
    if not _python_version_matches(preparation.python_version, observed_python):
        raise _reject("Execution Python version does not satisfy the dependency plan.")
    _true(
        runner.get("image_resolved_once_before_resource_creation"),
        "image resolution ordering",
    )
    _validate_volume_policy(execution.get("volume_policy"))
    download = _validate_phase(
        execution.get("download"),
        phase="download",
        network="bridge",
        image_id=preparation.image_id,
        policy=preparation.policy,
        mounts=[["input", "/input", False], ["wheelhouse", "/wheelhouse", True]],
    )
    install = _validate_phase(
        execution.get("install"),
        phase="install",
        network="none",
        image_id=preparation.image_id,
        policy=preparation.policy,
        mounts=[
            ["dependencies", "/dependencies", True],
            ["input", "/input", False],
            ["wheelhouse", "/wheelhouse", False],
        ],
    )
    sequence_sha256 = _validate_causality(
        execution.get("causality"),
        preparation=preparation,
        download=download,
        install=install,
    )
    cleanup = _exact_object(execution.get("cleanup"), _CLEANUP_KEYS, "execution cleanup")
    expected_cleanup = {
        "input_volume_removed": True,
        "wheelhouse_volume_removed": True,
        "dependency_volume_retained_inside_executor_context": True,
        "label_verification_required": True,
        "blind_force_volume_removal": False,
    }
    if cleanup != expected_cleanup:
        raise _reject("Dependency cleanup evidence does not match the executor contract.")
    return sequence_sha256


def _validate_volume_policy(value: object) -> None:
    policy = _exact_object(
        value,
        {role for role, _, _ in DEPENDENCY_VOLUME_QUOTA_CONTRACT},
        "dependency volume policy",
    )
    for role, size_bytes, max_inodes in DEPENDENCY_VOLUME_QUOTA_CONTRACT:
        observed = _exact_object(policy.get(role), _VOLUME_POLICY_KEYS, f"{role} volume policy")
        expected = {
            "driver": "local",
            "type": "tmpfs",
            "read_only_retention_anchor": True,
            "size_bytes": size_bytes,
            "max_inodes": max_inodes,
            "uid": 65532,
            "gid": 65532,
            "mode": "0700",
            "labels": _LABEL_KEYS,
        }
        if observed != expected:
            raise _reject(f"{role.capitalize()} volume policy changed.")


def _validate_phase(
    value: object,
    *,
    phase: str,
    network: str,
    image_id: str,
    policy: SandboxPolicy,
    mounts: list[list[object]],
) -> dict[str, object]:
    observed = _exact_object(value, _PHASE_KEYS, f"{phase} phase")
    command_sha256 = _pattern(observed.get("command_sha256"), f"{phase} command SHA-256", _SHA256)
    if phase not in {"download", "install"}:  # pragma: no cover - internal contract
        raise _reject("Dependency phase is unsupported.")
    expected_command_sha256 = dependency_phase_command_sha256(cast(DependencyPhase, phase))
    _equal(command_sha256, expected_command_sha256, f"{phase} command SHA-256")
    expected_fields: dict[str, object] = {
        "phase": phase,
        "image_id": image_id,
        "network_mode": network,
        "user": "65532:65532",
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "healthcheck_disabled": True,
        "trusted_phase_command": True,
        "pids": policy.pids,
        "memory_bytes": policy.memory_bytes,
        "memory_swap_bytes": policy.memory_bytes,
        "nano_cpus": int(policy.cpus * 1_000_000_000),
        "mounts": mounts,
        "command_sha256": command_sha256,
    }
    for key, expected in expected_fields.items():
        _equal(observed.get(key), expected, f"{phase} {key}")
    config_sha256 = _pattern(observed.get("config_sha256"), f"{phase} policy SHA-256", _SHA256)
    expected_config_sha256 = hashlib.sha256(_canonical_json_bytes(expected_fields)).hexdigest()
    _equal(config_sha256, expected_config_sha256, f"{phase} policy SHA-256")
    outcome = _exact_object(observed.get("outcome"), _OUTCOME_KEYS, f"{phase} outcome")
    expected_outcome = {
        "phase": phase,
        "exit_code": 0,
        "oom_killed": False,
        "timed_out": False,
        "output_truncated": False,
    }
    if outcome != expected_outcome:
        raise _reject(f"{phase.capitalize()} outcome is not a bounded success.")
    return {"config_sha256": config_sha256, "network": network, "mounts": mounts}


def _validate_causality(
    value: object,
    *,
    preparation: _PreparationEvidence,
    download: Mapping[str, object],
    install: Mapping[str, object],
) -> str:
    causality = _exact_object(value, _CAUSALITY_KEYS, "execution causality")
    events = _list(causality.get("events"), "causality events")
    if len(events) != 6:
        raise _reject("Causality sequence must contain exactly six events.")
    parsed = [_object(event, f"causality event {index}") for index, event in enumerate(events, 1)]
    expected_states = [
        ExecutionState.VOLUMES_PROVEN_EMPTY.value,
        ExecutionState.INPUT_STAGED.value,
        ExecutionState.DOWNLOAD_COMPLETED.value,
        ExecutionState.WHEELHOUSE_ATTESTED.value,
        ExecutionState.INSTALL_COMPLETED.value,
        ExecutionState.ARTIFACTS_ATTESTED.value,
    ]
    event_keys = [
        {
            "ordinal",
            "state",
            "input_probe_sha256",
            "wheelhouse_probe_sha256",
            "dependency_probe_sha256",
        },
        {"ordinal", "state", "input_probe_sha256", "requirements_sha256"},
        {"ordinal", "state", "phase_policy_sha256", "network", "exit_code", "oom_killed"},
        {"ordinal", "state", "volume_probe_sha256", "wheelhouse_sha256"},
        {
            "ordinal",
            "state",
            "phase_policy_sha256",
            "network",
            "exit_code",
            "oom_killed",
            "dependency_preinstall_sha256",
        },
        {
            "ordinal",
            "state",
            "input_probe_sha256",
            "wheelhouse_volume_probe_sha256",
            "dependency_probe_sha256",
            "dependency_tree_sha256",
            "wheelhouse_sha256",
        },
    ]
    for index, event in enumerate(parsed):
        if set(event) != event_keys[index]:
            raise _reject(f"Causality event {index + 1} fields changed.")
        _equal(event.get("ordinal"), index + 1, f"causality event {index + 1} ordinal")
        _equal(event.get("state"), expected_states[index], f"causality event {index + 1} state")

    first = parsed[0]
    for key in ("input_probe_sha256", "wheelhouse_probe_sha256", "dependency_probe_sha256"):
        _equal(first.get(key), _EMPTY_PROBE_SHA256, f"empty volume {key}")
    second, third, fourth, fifth, sixth = parsed[1:]
    input_probe = _pattern(second.get("input_probe_sha256"), "staged input probe", _SHA256)
    if input_probe == _EMPTY_PROBE_SHA256:
        raise _reject("Staged requirements probe still identifies an empty volume.")
    _equal(
        second.get("requirements_sha256"),
        preparation.requirements_sha256,
        "requirements identity",
    )
    _equal(third.get("phase_policy_sha256"), download["config_sha256"], "download event policy")
    _equal(third.get("network"), download["network"], "download event network")
    _equal(third.get("exit_code"), 0, "download event exit code")
    _false(third.get("oom_killed"), "download event OOM")
    wheel_probe = _pattern(fourth.get("volume_probe_sha256"), "wheelhouse volume probe", _SHA256)
    if wheel_probe == _EMPTY_PROBE_SHA256:
        raise _reject("Downloaded wheelhouse probe still identifies an empty volume.")
    _equal(fourth.get("wheelhouse_sha256"), preparation.wheelhouse_sha256, "wheelhouse identity")
    _equal(fifth.get("phase_policy_sha256"), install["config_sha256"], "install event policy")
    _equal(fifth.get("network"), install["network"], "install event network")
    _equal(fifth.get("exit_code"), 0, "install event exit code")
    _false(fifth.get("oom_killed"), "install event OOM")
    _equal(
        fifth.get("dependency_preinstall_sha256"),
        _EMPTY_PROBE_SHA256,
        "pre-install dependency emptiness",
    )
    _equal(sixth.get("input_probe_sha256"), input_probe, "final requirements probe")
    _equal(
        sixth.get("wheelhouse_volume_probe_sha256"),
        wheel_probe,
        "final wheelhouse probe",
    )
    dependency_probe = _pattern(
        sixth.get("dependency_probe_sha256"), "dependency volume probe", _SHA256
    )
    if dependency_probe == _EMPTY_PROBE_SHA256:
        raise _reject("Final dependency volume probe still identifies an empty volume.")
    _equal(
        sixth.get("dependency_tree_sha256"),
        preparation.dependency_tree_sha256,
        "dependency tree identity",
    )
    _equal(
        sixth.get("wheelhouse_sha256"),
        preparation.wheelhouse_sha256,
        "final wheelhouse identity",
    )
    sequence_sha256 = _pattern(
        causality.get("sequence_sha256"), "causality sequence SHA-256", _SHA256
    )
    expected_sequence = hashlib.sha256(_canonical_json_bytes(events)).hexdigest()
    _equal(sequence_sha256, expected_sequence, "causality sequence SHA-256")

    rw_count = sum(
        1
        for phase in (download, install)
        for role, _destination, writable in cast(list[list[object]], phase["mounts"])
        if role == "dependencies" and writable is True
    )
    expected_flags = {
        "volumes_new_and_empty": True,
        "download_precedes_wheelhouse_attestation": True,
        "install_precedes_dependency_attestation": True,
        "wheelhouse_unchanged_across_install": True,
        "requirements_unchanged": True,
        "dependency_volume_rw_phase_count": rw_count,
        "download_source_mounted": False,
        "install_network": install["network"],
    }
    for key, expected in expected_flags.items():
        _equal(causality.get(key), expected, f"causality {key}")
    return sequence_sha256


def _read_bounded_regular(path: Path) -> bytes:
    if not isinstance(path, Path):
        raise TypeError("Dependency execution receipt path must be a Path")
    try:
        with open_regular_file(path) as stream:
            raw = stream.read(MAX_EXECUTION_RECEIPT_BYTES + 1)
    except OSError as exc:
        raise _reject("Unable to read dependency execution receipt safely.") from exc
    if len(raw) > MAX_EXECUTION_RECEIPT_BYTES:
        raise _reject("Dependency execution receipt exceeds 1 MiB.")
    return raw


def _decode_strict_json(raw: bytes) -> object:
    try:
        decoded = cast(
            object,
            json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            ),
        )
        _check_json_nesting(decoded)
        return decoded
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("Dependency execution receipt is not strict bounded UTF-8 JSON.") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"invalid JSON constant: {value}")


def _check_json_nesting(value: object, *, depth: int = 0) -> None:
    if depth > MAX_JSON_NESTING:
        raise ValueError("JSON nesting exceeds the policy limit")
    if isinstance(value, Mapping):
        for child in value.values():
            _check_json_nesting(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _check_json_nesting(child, depth=depth + 1)


def _reject_ephemeral_resource_names(value: object) -> None:
    if isinstance(value, str):
        if _EPHEMERAL_RESOURCE.search(value):
            raise _reject("Receipt leaks an ephemeral dependency resource name.")
    elif isinstance(value, Mapping):
        for key, child in value.items():
            _reject_ephemeral_resource_names(key)
            _reject_ephemeral_resource_names(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _reject_ephemeral_resource_names(child)


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
        raise _reject("Receipt cannot be represented as canonical JSON.") from exc


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    result = _object(value, label)
    if set(result) != keys:
        raise _reject(f"{label.capitalize()} fields do not match the frozen contract.")
    return result


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _reject(f"{label.capitalize()} must be an object.")
    return {cast(str, key): child for key, child in value.items()}


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise _reject(f"{label.capitalize()} must be an array.")
    return value


def _pattern(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not value.isascii() or pattern.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} is invalid.")
    return value


def _integer(value: object, label: str, *, minimum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise _reject(f"{label.capitalize()} is not a valid integer.")
    return value


def _number(value: object, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise _reject(f"{label.capitalize()} is not a valid number.")
    return value


def _true(value: object, label: str) -> None:
    if value is not True:
        raise _reject(f"{label.capitalize()} must be true.")


def _false(value: object, label: str) -> None:
    if value is not False:
        raise _reject(f"{label.capitalize()} must be false.")


def _equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise _reject(f"{label.capitalize()} does not match the causal contract.")


def _bind_expected(
    actual: str,
    expected: str | None,
    label: str,
    pattern: re.Pattern[str],
) -> None:
    if expected is None:
        return
    if not isinstance(expected, str) or pattern.fullmatch(expected) is None:
        raise ValueError(f"Expected {label} is invalid")
    if actual != expected:
        raise _reject(f"{label.capitalize()} does not match the expected identity.")


def _python_version_matches(planned: str, observed: str) -> bool:
    planned_parts = planned.split(".")
    observed_parts = observed.split(".")
    return observed_parts[: len(planned_parts)] == planned_parts


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("dependency_execution_receipt", message)
