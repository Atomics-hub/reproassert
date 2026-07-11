from __future__ import annotations

import hashlib
import os
import re
import shutil
from collections.abc import Callable, Mapping
from dataclasses import asdict
from pathlib import Path
from typing import cast

from reproassert import __version__
from reproassert.benchmark_source import (
    BENCHMARK_VERSION,
    MAX_RECEIPT_BYTES,
    SOURCE_ARCHIVE_FILENAME,
    FrozenSourceCase,
    FrozenSourceManifest,
    _allocate_scratch,
    _ascii_pattern,
    _bounded_ascii,
    _canonical_json_bytes,
    _decode_strict_json,
    _exact_object,
    _hash_regular_file,
    _nonnegative_integer,
    _read_bounded_regular,
    _remove_scratch_checked,
    _require_equal,
    _stage_regular_file,
    _timeout,
    load_frozen_manifest,
)
from reproassert.codeload_transport import (
    CodeloadAcquisition,
    CodeloadRepairPlan,
    complete_codeload_repairs,
    plan_codeload_repairs,
)
from reproassert.errors import PolicyRejection
from reproassert.git_objects import (
    GIT_OBJECT_CONTENT_TREE_ALGORITHM,
    GIT_OBJECT_SNAPSHOT_ALGORITHM,
    MAX_GIT_TREE_JSON_BYTES,
    GitObjectLimits,
    GitObjectSnapshot,
    MaterializedGitWorkspace,
    fetch_recursive_git_tree,
    materialize_git_workspace,
)
from reproassert.github_blobs import fetch_raw_git_blob
from reproassert.intake import (
    GITHUB_API_HOST,
    GITHUB_CODELOAD_HOST,
    MAX_ARCHIVE_BYTES,
    MAX_COMMIT_JSON_BYTES,
    ArchiveDownload,
    CommitTreeMetadata,
    download_source_archive,
    fetch_commit_tree_metadata,
)
from reproassert.safeio import require_private_directory, write_bytes_exclusive

OBJECT_SOURCE_RECEIPT_SCHEMA_VERSION = "2.0.0"
OBJECT_SOURCE_RECEIPT_FILENAME = "benchmark-object-source-receipt.json"
OBJECT_SOURCE_DIRECTORY_SUFFIX = "-object-v2"
OBJECT_SOURCE_WORKSPACE_NAME = "workspace"
MAX_FALLBACK_BLOBS = 64

_GIT_OID = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CASE_ID = re.compile(r"rk-v0\.1-[0-9]{3}")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}")

_ROOT_KEYS = {
    "schema_version",
    "kind",
    "benchmark_version",
    "case",
    "manifest",
    "source",
    "acquisition",
    "tool",
    "campaign_readiness_changed",
}
_CASE_KEYS = {"id", "repository", "issue_url", "issue_number", "base_sha"}
_MANIFEST_KEYS = {"raw_sha256", "case_entry_sha256"}
_SOURCE_KEYS = {
    "repository_url",
    "base_sha",
    "github_root_tree_oid",
    "object_snapshot",
    "transport",
    "verified_workspace",
}
_SNAPSHOT_KEYS = {
    "algorithm",
    "manifest_sha256",
    "entry_count",
    "blob_count",
    "regular_file_count",
    "directory_count",
    "symlink_count",
    "gitlink_count",
    "total_blob_bytes",
}
_TRANSPORT_KEYS = {
    "path",
    "sha256",
    "bytes",
    "member_count",
    "regular_count",
    "directory_count",
    "symlink_count",
    "exact_blob_count",
    "repairs",
    "fallback_blob_oids",
}
_REPAIR_KEYS = {"path", "expected_oid", "reason", "observed_oid"}
_WORKSPACE_KEYS = {
    "algorithm",
    "tree_sha256",
    "git_root_tree_oid",
    "object_manifest_sha256",
    "regular_file_count",
    "directory_count",
    "symlink_count",
    "gitlink_count",
    "git_metadata_absent",
    "symlinks_root_confined",
    "gitlinks_uninitialized",
    "workspace_retained",
}
_ACQUISITION_KEYS = {"policy", "policy_sha256", "runtime"}
_RUNTIME_KEYS = {"http_timeout_seconds"}
_TOOL_KEYS = {"name", "version", "git_sha"}

DEFAULT_OBJECT_LIMITS = GitObjectLimits()


def object_source_acquisition_policy() -> dict[str, object]:
    return {
        "id": "github-exact-object-source-v2",
        "network": {
            "scheme": "https",
            "metadata_and_blob_host": GITHUB_API_HOST,
            "archive_host": GITHUB_CODELOAD_HOST,
            "authentication": "none",
            "proxy_environment": "disabled",
            "redirects": "rejected",
            "tls_minimum": "1.2",
            "commit_metadata_max_bytes": MAX_COMMIT_JSON_BYTES,
            "recursive_tree_max_bytes": MAX_GIT_TREE_JSON_BYTES,
        },
        "tree": {
            "source": "recursive_git_trees_api_exact_root_oid",
            "truncated_responses": "reject",
            "root_binding": "reconstructed_tree_oid_equals_commit_root_tree_oid",
            "mode_mapping": "api_040000_serializes_as_git_40000",
        },
        "transport": {
            "source": "codeload_full_40_hex_commit_sha",
            "format": "tar.gz",
            "preserved_filename": SOURCE_ARCHIVE_FILENAME,
            "max_compressed_bytes": MAX_ARCHIVE_BYTES,
            "parser": "bounded_stream_no_extraction",
            "extra_duplicate_special_and_unsafe_members": "reject",
            "identity": "bulk_transport_only_not_git_identity",
        },
        "repair": {
            "source": "git_blobs_raw_api_by_exact_oid",
            "selection": "missing_or_oid_mismatched_blobs_only",
            "authentication": "none",
            "max_fallback_blobs": MAX_FALLBACK_BLOBS,
            "retries": 0,
        },
        "verification": {
            "snapshot_algorithm": GIT_OBJECT_SNAPSHOT_ALGORITHM,
            "content_tree_algorithm": GIT_OBJECT_CONTENT_TREE_ALGORITHM,
            "limits": asdict(DEFAULT_OBJECT_LIMITS),
            "blob_identity": "git_sha1_verified_then_content_sha256_committed",
            "symlinks": "tracked_blob_verified_transitively_root_confined",
            "gitlinks": "attested_commit_oid_uninitialized_empty_directory",
            "submodule_recursion": "disabled",
        },
        "workspace": {
            "git_metadata": "absent",
            "materialization": "controller_owned_private_directory",
            "retention_after_validation": "removed_before_receipt_write",
        },
    }


_OBJECT_SOURCE_POLICY = object_source_acquisition_policy()
OBJECT_SOURCE_POLICY_SHA256 = hashlib.sha256(
    _canonical_json_bytes(_OBJECT_SOURCE_POLICY)
).hexdigest()

RawBlobFetcher = Callable[..., bytes]


def prepare_object_source_case(
    manifest_path: Path,
    case_id: str,
    output_root: Path,
    *,
    tool_git_sha: str,
    timeout_seconds: float = 15.0,
    blob_fetcher: RawBlobFetcher = fetch_raw_git_blob,
) -> Path:
    """Prepare one exact-object source receipt without generation or repository execution."""

    manifest = load_frozen_manifest(manifest_path)
    case = manifest.require_case(case_id)
    producer_git_sha = _ascii_pattern(tool_git_sha, "tool Git SHA", _GIT_OID)
    timeout = _timeout(timeout_seconds, "acquisition timeout")
    root = Path(output_root)
    require_private_directory(root)
    case_dir = root / f"{case.id}{OBJECT_SOURCE_DIRECTORY_SUFFIX}"
    created = False
    try:
        try:
            case_dir.mkdir(mode=0o700)
            created = True
        except FileExistsError as exc:
            raise _reject(f"Refusing to overwrite object-source preparation: {case_dir}") from exc
        os.chmod(case_dir, 0o700, follow_symlinks=False)
        require_private_directory(case_dir)
        commit, snapshot, archive, repair_plan, acquisition, materialized = (
            _acquire_and_materialize(
                case,
                case_dir,
                timeout_seconds=timeout,
                blob_fetcher=blob_fetcher,
            )
        )
        _remove_workspace(materialized.path)
        _require_archive_unchanged(archive, repair_plan)
        receipt = _build_receipt(
            manifest=manifest,
            case=case,
            commit=commit,
            snapshot=snapshot,
            archive=archive,
            repair_plan=repair_plan,
            acquisition=acquisition,
            materialized=materialized,
            timeout_seconds=timeout,
            tool_version=__version__,
            tool_git_sha=producer_git_sha,
        )
        _validate_receipt_shape(receipt)
        receipt_bytes = _canonical_json_bytes(receipt) + b"\n"
        if len(receipt_bytes) > MAX_RECEIPT_BYTES:
            raise _reject("Object-source receipt exceeds the byte limit.")
        receipt_path = case_dir / OBJECT_SOURCE_RECEIPT_FILENAME
        write_bytes_exclusive(receipt_path, receipt_bytes)
        return receipt_path
    except BaseException:
        if created:
            shutil.rmtree(case_dir, ignore_errors=True)
        raise


def verify_object_source_receipt(
    receipt_path: Path,
    *,
    manifest_path: Path,
    expected_case_id: str,
    expected_receipt_sha256: str | None = None,
    scratch_root: Path | None = None,
    timeout_seconds: float = 15.0,
    blob_fetcher: RawBlobFetcher = fetch_raw_git_blob,
) -> dict[str, object]:
    """Freshly rederive source evidence while preserving structural producer metadata.

    ``tool`` and the recorded runtime are validated and replayed, not independently
    authenticated. Supply a trusted ``expected_receipt_sha256`` when producer provenance matters.
    """

    manifest = load_frozen_manifest(manifest_path)
    case = manifest.require_case(expected_case_id)
    timeout = _timeout(timeout_seconds, "verification timeout")
    path = Path(receipt_path)
    raw = _read_bounded_regular(path, MAX_RECEIPT_BYTES, "object-source receipt")
    actual_receipt_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_receipt_sha256 is not None:
        expected_hash = _ascii_pattern(expected_receipt_sha256, "expected receipt SHA-256", _SHA256)
        _require_equal(actual_receipt_sha256, expected_hash, "receipt SHA-256")
    decoded = _decode_strict_json(raw, "object-source receipt")
    if raw != _canonical_json_bytes(decoded) + b"\n":
        raise _reject("Object-source receipt is not canonical JSON with one final newline.")
    receipt = _validate_receipt_shape(decoded)
    _validate_manifest_binding(receipt, manifest, case)
    archive_path = path.parent / SOURCE_ARCHIVE_FILENAME
    scratch = _allocate_scratch(scratch_root)
    try:
        staged_archive = _stage_regular_file(
            archive_path,
            scratch / SOURCE_ARCHIVE_FILENAME,
            max_bytes=MAX_ARCHIVE_BYTES,
        )
        commit, snapshot, repair_plan, acquisition, materialized = _verify_staged_archive(
            case,
            staged_archive,
            scratch,
            timeout_seconds=timeout,
            blob_fetcher=blob_fetcher,
        )
        _remove_workspace(materialized.path)
        _require_archive_unchanged(staged_archive, repair_plan)
        acquisition_record = cast(dict[str, object], receipt["acquisition"])
        runtime = cast(dict[str, object], acquisition_record["runtime"])
        tool = cast(dict[str, object], receipt["tool"])
        expected = _build_receipt(
            manifest=manifest,
            case=case,
            commit=commit,
            snapshot=snapshot,
            archive=staged_archive,
            repair_plan=repair_plan,
            acquisition=acquisition,
            materialized=materialized,
            timeout_seconds=cast(float, runtime["http_timeout_seconds"]),
            tool_version=cast(str, tool["version"]),
            tool_git_sha=cast(str, tool["git_sha"]),
        )
        if receipt != expected:
            raise _reject("Object-source receipt fields do not match freshly derived values.")
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    _remove_scratch_checked(scratch)
    return receipt


def _acquire_and_materialize(
    case: FrozenSourceCase,
    case_dir: Path,
    *,
    timeout_seconds: float,
    blob_fetcher: RawBlobFetcher,
) -> tuple[
    CommitTreeMetadata,
    GitObjectSnapshot,
    ArchiveDownload,
    CodeloadRepairPlan,
    CodeloadAcquisition,
    MaterializedGitWorkspace,
]:
    commit = fetch_commit_tree_metadata(
        case.owner, case.repo, case.base_sha, timeout_seconds=timeout_seconds
    )
    if commit.commit_sha != case.base_sha:
        raise _reject("Commit metadata does not match the frozen base SHA.")
    snapshot = fetch_recursive_git_tree(
        case.owner,
        case.repo,
        commit.tree_sha,
        timeout_seconds=timeout_seconds,
        limits=DEFAULT_OBJECT_LIMITS,
    )
    archive = download_source_archive(
        case.owner,
        case.repo,
        case.base_sha,
        case_dir,
        timeout_seconds=timeout_seconds,
    )
    repair_plan, acquisition = _complete_transport(
        case,
        snapshot,
        archive,
        timeout_seconds=timeout_seconds,
        blob_fetcher=blob_fetcher,
    )
    materialized = materialize_git_workspace(
        acquisition.verified_plan, case_dir / OBJECT_SOURCE_WORKSPACE_NAME
    )
    return commit, snapshot, archive, repair_plan, acquisition, materialized


def _verify_staged_archive(
    case: FrozenSourceCase,
    archive: ArchiveDownload,
    scratch: Path,
    *,
    timeout_seconds: float,
    blob_fetcher: RawBlobFetcher,
) -> tuple[
    CommitTreeMetadata,
    GitObjectSnapshot,
    CodeloadRepairPlan,
    CodeloadAcquisition,
    MaterializedGitWorkspace,
]:
    commit = fetch_commit_tree_metadata(
        case.owner, case.repo, case.base_sha, timeout_seconds=timeout_seconds
    )
    if commit.commit_sha != case.base_sha:
        raise _reject("Fresh commit metadata does not match the frozen base SHA.")
    snapshot = fetch_recursive_git_tree(
        case.owner,
        case.repo,
        commit.tree_sha,
        timeout_seconds=timeout_seconds,
        limits=DEFAULT_OBJECT_LIMITS,
    )
    repair_plan, acquisition = _complete_transport(
        case,
        snapshot,
        archive,
        timeout_seconds=timeout_seconds,
        blob_fetcher=blob_fetcher,
    )
    materialized = materialize_git_workspace(
        acquisition.verified_plan, scratch / OBJECT_SOURCE_WORKSPACE_NAME
    )
    return commit, snapshot, repair_plan, acquisition, materialized


def _complete_transport(
    case: FrozenSourceCase,
    snapshot: GitObjectSnapshot,
    archive: ArchiveDownload,
    *,
    timeout_seconds: float,
    blob_fetcher: RawBlobFetcher,
) -> tuple[CodeloadRepairPlan, CodeloadAcquisition]:
    repair_plan = plan_codeload_repairs(snapshot, archive.path, limits=DEFAULT_OBJECT_LIMITS)
    if (
        len(repair_plan.repairs) > MAX_FALLBACK_BLOBS
        or len(repair_plan.repair_oids) > MAX_FALLBACK_BLOBS
    ):
        raise PolicyRejection(
            "object_source_repair_limit",
            "Exact-object source requires more fallback blobs than policy permits.",
        )
    size_by_oid: dict[str, int] = {}
    for entry in snapshot.entries:
        if not (entry.is_regular or entry.is_symlink):
            continue
        if entry.size is None:
            raise _reject("Git blob entry is missing its declared size.")
        prior = size_by_oid.setdefault(entry.oid, entry.size)
        if prior != entry.size:
            raise _reject("Git blob OID has conflicting declared sizes.")

    def fetch_one(oid: str) -> bytes:
        if oid not in repair_plan.repair_oids:
            raise _reject("Fallback loader was asked for an unplanned Git blob.")
        return blob_fetcher(
            case.owner,
            case.repo,
            oid,
            expected_size=size_by_oid[oid],
            timeout_seconds=timeout_seconds,
        )

    acquisition = complete_codeload_repairs(
        snapshot,
        repair_plan,
        fetch_one,
        limits=DEFAULT_OBJECT_LIMITS,
    )
    return repair_plan, acquisition


def _build_receipt(
    *,
    manifest: FrozenSourceManifest,
    case: FrozenSourceCase,
    commit: CommitTreeMetadata,
    snapshot: GitObjectSnapshot,
    archive: ArchiveDownload,
    repair_plan: CodeloadRepairPlan,
    acquisition: CodeloadAcquisition,
    materialized: MaterializedGitWorkspace,
    timeout_seconds: float,
    tool_version: str,
    tool_git_sha: str,
) -> dict[str, object]:
    return {
        "schema_version": OBJECT_SOURCE_RECEIPT_SCHEMA_VERSION,
        "kind": "benchmark_object_source_receipt",
        "benchmark_version": manifest.benchmark_version,
        "case": {
            "id": case.id,
            "repository": case.repository,
            "issue_url": case.issue_url,
            "issue_number": case.issue_number,
            "base_sha": case.base_sha,
        },
        "manifest": {
            "raw_sha256": manifest.raw_sha256,
            "case_entry_sha256": case.case_entry_sha256,
        },
        "source": {
            "repository_url": f"https://github.com/{case.repository}",
            "base_sha": case.base_sha,
            "github_root_tree_oid": commit.tree_sha,
            "object_snapshot": {
                "algorithm": snapshot.algorithm,
                "manifest_sha256": snapshot.manifest_sha256,
                "entry_count": snapshot.entry_count,
                "blob_count": snapshot.blob_count,
                "regular_file_count": snapshot.regular_file_count,
                "directory_count": snapshot.directory_count,
                "symlink_count": snapshot.symlink_count,
                "gitlink_count": snapshot.gitlink_count,
                "total_blob_bytes": snapshot.total_blob_bytes,
            },
            "transport": {
                "path": SOURCE_ARCHIVE_FILENAME,
                "sha256": archive.sha256,
                "bytes": archive.size_bytes,
                "member_count": repair_plan.archive_member_count,
                "regular_count": repair_plan.archive_regular_count,
                "directory_count": repair_plan.archive_directory_count,
                "symlink_count": repair_plan.archive_symlink_count,
                "exact_blob_count": len(repair_plan.exact_blobs),
                "repairs": [
                    {
                        "path": repair.path,
                        "expected_oid": repair.expected_oid,
                        "reason": repair.reason,
                        "observed_oid": repair.observed_oid,
                    }
                    for repair in repair_plan.repairs
                ],
                "fallback_blob_oids": list(repair_plan.repair_oids),
            },
            "verified_workspace": {
                "algorithm": GIT_OBJECT_CONTENT_TREE_ALGORITHM,
                "tree_sha256": acquisition.verified_plan.tree_sha256,
                "git_root_tree_oid": materialized.root_tree_oid,
                "object_manifest_sha256": materialized.manifest_sha256,
                "regular_file_count": materialized.regular_file_count,
                "directory_count": materialized.directory_count,
                "symlink_count": materialized.symlink_count,
                "gitlink_count": materialized.gitlink_count,
                "git_metadata_absent": True,
                "symlinks_root_confined": True,
                "gitlinks_uninitialized": True,
                "workspace_retained": False,
            },
        },
        "acquisition": {
            "policy": object_source_acquisition_policy(),
            "policy_sha256": OBJECT_SOURCE_POLICY_SHA256,
            "runtime": {"http_timeout_seconds": timeout_seconds},
        },
        "tool": {"name": "reproassert", "version": tool_version, "git_sha": tool_git_sha},
        "campaign_readiness_changed": False,
    }


def _validate_receipt_shape(
    value: object,
    *,
    benchmark_version: str = BENCHMARK_VERSION,
    case_id_pattern: re.Pattern[str] = _CASE_ID,
) -> dict[str, object]:
    root = _exact_object(value, _ROOT_KEYS, "object-source receipt")
    _require_equal(
        root.get("schema_version"), OBJECT_SOURCE_RECEIPT_SCHEMA_VERSION, "schema version"
    )
    _require_equal(root.get("kind"), "benchmark_object_source_receipt", "receipt kind")
    _require_equal(root.get("benchmark_version"), benchmark_version, "benchmark version")
    if root.get("campaign_readiness_changed") is not False:
        raise _reject("Object-source receipt cannot change campaign readiness.")
    case = _exact_object(root.get("case"), _CASE_KEYS, "object-source case")
    _ascii_pattern(case.get("id"), "case id", case_id_pattern)
    _ascii_pattern(case.get("repository"), "repository", _REPOSITORY)
    _bounded_ascii(case.get("issue_url"), "issue URL", 512)
    _nonnegative_integer(case.get("issue_number"), "issue number", positive=True)
    _ascii_pattern(case.get("base_sha"), "base SHA", _GIT_OID)
    manifest = _exact_object(root.get("manifest"), _MANIFEST_KEYS, "object-source manifest")
    _ascii_pattern(manifest.get("raw_sha256"), "manifest SHA-256", _SHA256)
    _ascii_pattern(manifest.get("case_entry_sha256"), "case entry SHA-256", _SHA256)
    source = _exact_object(root.get("source"), _SOURCE_KEYS, "object-source source")
    _bounded_ascii(source.get("repository_url"), "repository URL", 512)
    _ascii_pattern(source.get("base_sha"), "source base SHA", _GIT_OID)
    _ascii_pattern(source.get("github_root_tree_oid"), "root tree OID", _GIT_OID)
    snapshot = _exact_object(source.get("object_snapshot"), _SNAPSHOT_KEYS, "object snapshot")
    _require_equal(snapshot.get("algorithm"), GIT_OBJECT_SNAPSHOT_ALGORITHM, "snapshot algorithm")
    _ascii_pattern(snapshot.get("manifest_sha256"), "object manifest SHA-256", _SHA256)
    for key in _SNAPSHOT_KEYS - {"algorithm", "manifest_sha256"}:
        _nonnegative_integer(snapshot.get(key), f"snapshot {key}")
    transport = _exact_object(source.get("transport"), _TRANSPORT_KEYS, "object transport")
    _require_equal(transport.get("path"), SOURCE_ARCHIVE_FILENAME, "archive path")
    _ascii_pattern(transport.get("sha256"), "archive SHA-256", _SHA256)
    for key in _TRANSPORT_KEYS - {
        "path",
        "sha256",
        "repairs",
        "fallback_blob_oids",
    }:
        _nonnegative_integer(transport.get(key), f"transport {key}")
    repairs = transport.get("repairs")
    if not isinstance(repairs, list) or len(repairs) > MAX_FALLBACK_BLOBS:
        raise _reject("Object transport repairs are invalid or exceed the limit.")
    for raw_repair in repairs:
        repair = _exact_object(raw_repair, _REPAIR_KEYS, "object transport repair")
        _bounded_utf8(repair.get("path"), "repair path", 4096)
        _ascii_pattern(repair.get("expected_oid"), "repair expected OID", _GIT_OID)
        if repair.get("reason") not in {"missing", "blob_oid_mismatch"}:
            raise _reject("Object transport repair reason is invalid.")
        observed_oid = repair.get("observed_oid")
        if observed_oid is not None:
            _ascii_pattern(observed_oid, "repair observed OID", _GIT_OID)
    fallback = transport.get("fallback_blob_oids")
    if not isinstance(fallback, list) or len(fallback) > MAX_FALLBACK_BLOBS:
        raise _reject("Fallback blob OIDs are not a bounded canonical list.")
    for oid in fallback:
        _ascii_pattern(oid, "fallback blob OID", _GIT_OID)
    if fallback != sorted(set(fallback)):
        raise _reject("Fallback blob OIDs are not a bounded canonical list.")
    workspace = _exact_object(
        source.get("verified_workspace"), _WORKSPACE_KEYS, "verified object workspace"
    )
    _require_equal(
        workspace.get("algorithm"), GIT_OBJECT_CONTENT_TREE_ALGORITHM, "workspace algorithm"
    )
    _ascii_pattern(workspace.get("tree_sha256"), "workspace tree SHA-256", _SHA256)
    _ascii_pattern(workspace.get("git_root_tree_oid"), "workspace Git tree OID", _GIT_OID)
    _ascii_pattern(workspace.get("object_manifest_sha256"), "workspace manifest SHA-256", _SHA256)
    for key in {
        "regular_file_count",
        "directory_count",
        "symlink_count",
        "gitlink_count",
    }:
        _nonnegative_integer(workspace.get(key), f"workspace {key}")
    for key in {"git_metadata_absent", "symlinks_root_confined", "gitlinks_uninitialized"}:
        if workspace.get(key) is not True:
            raise _reject(f"Verified workspace {key} must be true.")
    if workspace.get("workspace_retained") is not False:
        raise _reject("Verified workspace must be removed before receipt creation.")
    acquisition = _exact_object(
        root.get("acquisition"), _ACQUISITION_KEYS, "object-source acquisition"
    )
    if acquisition.get("policy") != _OBJECT_SOURCE_POLICY:
        raise _reject("Object-source receipt acquisition policy is not frozen.")
    _require_equal(
        acquisition.get("policy_sha256"),
        OBJECT_SOURCE_POLICY_SHA256,
        "acquisition policy SHA-256",
    )
    runtime = _exact_object(acquisition.get("runtime"), _RUNTIME_KEYS, "acquisition runtime")
    _timeout(runtime.get("http_timeout_seconds"), "recorded HTTP timeout")
    tool = _exact_object(root.get("tool"), _TOOL_KEYS, "object-source tool")
    _require_equal(tool.get("name"), "reproassert", "tool name")
    _ascii_pattern(tool.get("version"), "tool version", _VERSION)
    _ascii_pattern(tool.get("git_sha"), "tool Git SHA", _GIT_OID)
    return root


def _validate_manifest_binding(
    receipt: Mapping[str, object],
    manifest: FrozenSourceManifest,
    case: FrozenSourceCase,
) -> None:
    expected_case: dict[str, object] = {
        "id": case.id,
        "repository": case.repository,
        "issue_url": case.issue_url,
        "issue_number": case.issue_number,
        "base_sha": case.base_sha,
    }
    if receipt["case"] != expected_case:
        raise _reject("Object-source receipt does not match the requested case.")
    expected_manifest = {
        "raw_sha256": manifest.raw_sha256,
        "case_entry_sha256": case.case_entry_sha256,
    }
    if receipt["manifest"] != expected_manifest:
        raise _reject("Object-source receipt does not match the frozen manifest.")


def _require_archive_unchanged(archive: ArchiveDownload, repair_plan: CodeloadRepairPlan) -> None:
    observed_sha256, observed_bytes = _hash_regular_file(archive.path, max_bytes=MAX_ARCHIVE_BYTES)
    expected = (archive.sha256, archive.size_bytes)
    if (observed_sha256, observed_bytes) != expected or (
        repair_plan.archive_sha256,
        repair_plan.archive_bytes,
    ) != expected:
        raise _reject("Codeload archive changed during exact-object preparation.")


def _remove_workspace(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except OSError as exc:
        raise _reject("Unable to remove the temporary exact-object workspace.") from exc
    if path.exists() or path.is_symlink():
        raise _reject("Temporary exact-object workspace remains after cleanup.")


def _bounded_utf8(value: object, label: str, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise _reject(f"{label.capitalize()} is not bounded UTF-8 text.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise _reject(f"{label.capitalize()} is not bounded UTF-8 text.") from exc
    if len(encoded) > maximum_bytes:
        raise _reject(f"{label.capitalize()} exceeds the UTF-8 byte limit.")
    return value


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_object_source_receipt", message)
