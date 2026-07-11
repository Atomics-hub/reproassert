"""Exact Git-object source preparation bound to the frozen v0.2 cohort plan."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, cast

from reproassert import __version__
from reproassert.benchmark_object_source import (
    OBJECT_SOURCE_DIRECTORY_SUFFIX,
    OBJECT_SOURCE_RECEIPT_FILENAME,
    RawBlobFetcher,
    _acquire_and_materialize,
    _build_receipt,
    _remove_workspace,
    _require_archive_unchanged,
    _validate_manifest_binding,
    _validate_receipt_shape,
    _verify_staged_archive,
)
from reproassert.benchmark_source import (
    MAX_RECEIPT_BYTES,
    SOURCE_ARCHIVE_FILENAME,
    FrozenSourceCase,
    FrozenSourceManifest,
    _allocate_scratch,
    _ascii_pattern,
    _canonical_json_bytes,
    _decode_strict_json,
    _hash_regular_file,
    _read_bounded_regular,
    _remove_scratch_checked,
    _stage_regular_file,
    _timeout,
)
from reproassert.benchmark_v02_cohort import load_v02_leak_audited_cohort_plan
from reproassert.errors import PolicyRejection
from reproassert.git_objects import VerifiedGitObjectPlan
from reproassert.github_blobs import fetch_raw_git_blob
from reproassert.intake import MAX_ARCHIVE_BYTES, parse_issue_url
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

if TYPE_CHECKING:
    from reproassert.semantic_issuer import VerifiedV02SourceEvidence

V02_BENCHMARK_VERSION = "0.2.0"
V02_OBJECT_SOURCE_DIRECTORY_SUFFIX = OBJECT_SOURCE_DIRECTORY_SUFFIX
V02_OBJECT_SOURCE_RECEIPT_FILENAME = OBJECT_SOURCE_RECEIPT_FILENAME
FROZEN_V02_COHORT_PLAN_SHA256 = "20d8e5cac69f51419caf134b4a1adcd2c819e15f078e9e9dd1c11ce717a1c31c"

_V02_CASE_ID = re.compile(r"rk-v0\.2-(?:00[1-9]|01[0-9]|020)")
_GIT_OID = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def load_v02_object_source_plan(plan_path: Path) -> FrozenSourceManifest:
    """Load the frozen ordered cohort as exact-source identities.

    The cohort validator checks its self-hash, every case hash, and the canonical
    ``rk-v0.2-001`` through ``rk-v0.2-020`` ordering before this projection is made.
    """

    path = Path(plan_path)
    plan = load_v02_leak_audited_cohort_plan(path)
    if plan.get("cohort_plan_sha256") != FROZEN_V02_COHORT_PLAN_SHA256:
        raise _reject("Cohort plan does not match the frozen v0.2 selection commitment.")
    raw_sha256, _ = _hash_regular_file(path, max_bytes=512 * 1024)
    cases: list[FrozenSourceCase] = []
    for raw in cast(list[object], plan["cases"]):
        case = cast(dict[str, object], raw)
        issue_url = cast(str, case["issue_url"])
        location = parse_issue_url(issue_url)
        repository = cast(str, case["repo"])
        if f"{location.owner}/{location.repo}" != repository:
            raise _reject("Cohort repository and issue URL identities differ.")
        cases.append(
            FrozenSourceCase(
                id=cast(str, case["case_id"]),
                repository=repository,
                issue_url=issue_url,
                issue_number=location.number,
                base_sha=cast(str, case["base_sha"]),
                case_entry_sha256=cast(str, case["case_plan_sha256"]),
            )
        )
    return FrozenSourceManifest(
        path=path,
        raw_sha256=raw_sha256,
        benchmark_version=V02_BENCHMARK_VERSION,
        cases=tuple(cases),
    )


def prepare_v02_object_source_case(
    plan_path: Path,
    case_id: str,
    output_root: Path,
    *,
    tool_git_sha: str,
    timeout_seconds: float = 15.0,
    blob_fetcher: RawBlobFetcher = fetch_raw_git_blob,
) -> Path:
    """Prepare one v0.2 exact-object receipt without executing repository code."""

    plan = load_v02_object_source_plan(plan_path)
    case = plan.require_case(_ascii_pattern(case_id, "case id", _V02_CASE_ID))
    producer_git_sha = _ascii_pattern(tool_git_sha, "tool Git SHA", _GIT_OID)
    timeout = _timeout(timeout_seconds, "acquisition timeout")
    root = Path(output_root)
    require_private_directory(root)
    case_dir = root / f"{case.id}{V02_OBJECT_SOURCE_DIRECTORY_SUFFIX}"
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
            manifest=plan,
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
        _validate_v02_receipt(receipt)
        receipt_bytes = _canonical_json_bytes(receipt) + b"\n"
        if len(receipt_bytes) > MAX_RECEIPT_BYTES:
            raise _reject("Object-source receipt exceeds the byte limit.")
        receipt_path = case_dir / V02_OBJECT_SOURCE_RECEIPT_FILENAME
        write_bytes_exclusive(receipt_path, receipt_bytes)
        return receipt_path
    except BaseException:
        if created:
            shutil.rmtree(case_dir, ignore_errors=True)
        raise


def verify_v02_object_source_receipt(
    receipt_path: Path,
    *,
    plan_path: Path,
    expected_case_id: str,
    expected_receipt_sha256: str | None = None,
    scratch_root: Path | None = None,
    timeout_seconds: float = 15.0,
    blob_fetcher: RawBlobFetcher = fetch_raw_git_blob,
) -> dict[str, object]:
    """Freshly rederive and verify one v0.2 exact-object source receipt."""

    receipt, _, _ = _rederive_v02_object_source_receipt(
        receipt_path,
        plan_path=plan_path,
        expected_case_id=expected_case_id,
        expected_receipt_sha256=expected_receipt_sha256,
        scratch_root=scratch_root,
        timeout_seconds=timeout_seconds,
        blob_fetcher=blob_fetcher,
    )
    return receipt


def issue_v02_source_evidence_from_object_receipt(
    receipt_path: Path,
    *,
    plan_path: Path,
    expected_case_id: str,
    source_evidence_receipt_path: Path,
    expected_receipt_sha256: str | None = None,
    scratch_root: Path | None = None,
    timeout_seconds: float = 15.0,
    blob_fetcher: RawBlobFetcher = fetch_raw_git_blob,
) -> VerifiedV02SourceEvidence:
    """Freshly rederive persisted source bytes and issue process-local source authority."""

    from reproassert.benchmark_v02_package import (
        V02CaseIdentity,
        _require_outside_source_checkout,
    )
    from reproassert.semantic_issuer import (
        render_v02_source_evidence_receipt,
        verify_v02_source_evidence,
    )

    _, case, exact_plan = _rederive_v02_object_source_receipt(
        receipt_path,
        plan_path=plan_path,
        expected_case_id=expected_case_id,
        expected_receipt_sha256=expected_receipt_sha256,
        scratch_root=scratch_root,
        timeout_seconds=timeout_seconds,
        blob_fetcher=blob_fetcher,
    )
    identity = V02CaseIdentity(case.id, case.repository, case.issue_url, case.base_sha)
    content = render_v02_source_evidence_receipt(identity, exact_plan)
    evidence_path = Path(source_evidence_receipt_path)
    require_private_directory(evidence_path.parent)
    _require_outside_source_checkout(evidence_path.parent)
    if evidence_path.exists() or evidence_path.is_symlink():
        with open_regular_file(evidence_path) as stream:
            observed = stream.read(MAX_RECEIPT_BYTES + 1)
        if observed != content:
            raise _reject("Existing source evidence receipt differs from fresh rederivation.")
    else:
        write_bytes_exclusive(evidence_path, content)
    return verify_v02_source_evidence(
        evidence_path,
        case=identity,
        exact_object_plan=exact_plan,
    )


def _rederive_v02_object_source_receipt(
    receipt_path: Path,
    *,
    plan_path: Path,
    expected_case_id: str,
    expected_receipt_sha256: str | None,
    scratch_root: Path | None,
    timeout_seconds: float,
    blob_fetcher: RawBlobFetcher,
) -> tuple[dict[str, object], FrozenSourceCase, VerifiedGitObjectPlan]:
    """Return verified receipt data plus the fresh in-memory exact-object plan."""

    plan = load_v02_object_source_plan(plan_path)
    case_id = _ascii_pattern(expected_case_id, "case id", _V02_CASE_ID)
    case = plan.require_case(case_id)
    timeout = _timeout(timeout_seconds, "verification timeout")
    path = Path(receipt_path)
    raw = _read_bounded_regular(path, MAX_RECEIPT_BYTES, "object-source receipt")
    actual_receipt_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_receipt_sha256 is not None:
        expected_hash = _ascii_pattern(expected_receipt_sha256, "expected receipt SHA-256", _SHA256)
        if actual_receipt_sha256 != expected_hash:
            raise _reject("Receipt SHA-256 differs from the trusted expectation.")
    decoded = _decode_strict_json(raw, "object-source receipt")
    if raw != _canonical_json_bytes(decoded) + b"\n":
        raise _reject("Object-source receipt is not canonical JSON with one final newline.")
    receipt = _validate_v02_receipt(decoded)
    _validate_manifest_binding(receipt, plan, case)
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
            manifest=plan,
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
        exact_plan = acquisition.verified_plan
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    _remove_scratch_checked(scratch)
    return receipt, case, exact_plan


def _validate_v02_receipt(value: object) -> dict[str, object]:
    return _validate_receipt_shape(
        value,
        benchmark_version=V02_BENCHMARK_VERSION,
        case_id_pattern=_V02_CASE_ID,
    )


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_object_source", message)
