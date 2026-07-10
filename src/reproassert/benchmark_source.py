from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from reproassert import __version__
from reproassert.errors import PolicyRejection
from reproassert.intake import (
    GITHUB_API_HOST,
    GITHUB_CODELOAD_HOST,
    MAX_ARCHIVE_BYTES,
    MAX_COMMIT_JSON_BYTES,
    ArchiveDownload,
    CommitTreeMetadata,
    ExtractedArchive,
    ExtractionLimits,
    download_source_archive,
    extract_source_archive,
    fetch_commit_tree_metadata,
    parse_issue_url,
)
from reproassert.safeio import (
    create_private_run_dir,
    open_exclusive_file,
    open_regular_file,
    require_private_directory,
    write_bytes_exclusive,
)
from reproassert.source_attestation import (
    SOURCE_TREE_ALGORITHM,
    SourceAttestationLimits,
    SourceTreeAttestation,
    attest_source_tree,
)

SOURCE_RECEIPT_SCHEMA_VERSION = "1.0.0"
SOURCE_INDEX_SCHEMA_VERSION = "1.0.0"
BENCHMARK_VERSION = "0.1.0"
SOURCE_RECEIPT_FILENAME = "benchmark-source-receipt.json"
SOURCE_ARCHIVE_FILENAME = "source.tar.gz"
SOURCE_INDEX_FILENAME = "benchmark-source-index.json"

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
EXPECTED_CASE_COUNT = 20
FROZEN_MANIFEST_SHA256 = "f3e15d05f29269c6d1d067ea7327b63e9b40fcb1ef142c731a215a02b5ebbc8f"
MAX_HTTP_TIMEOUT_SECONDS = 300.0
MAX_JSON_NESTING = 128

_CASE_ID = re.compile(r"rk-v0\.1-[0-9]{3}")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}")

_MANIFEST_KEYS = {
    "benchmark_version",
    "name",
    "frozen_at",
    "status",
    "case_schema",
    "run_schema",
    "source",
    "selection",
    "protocol",
    "claim_ladder",
    "outcome_taxonomy",
    "gates",
    "cost_semantics",
    "contamination",
    "cases",
}
_CASE_KEYS = {"id", "repo", "issue_url", "base_sha", "difficulty", "title", "smoke"}
_RECEIPT_KEYS = {
    "schema_version",
    "benchmark_version",
    "case",
    "manifest",
    "source",
    "acquisition",
    "tool",
}
_RECEIPT_CASE_KEYS = {"id", "repository", "issue_url", "issue_number", "base_sha"}
_RECEIPT_MANIFEST_KEYS = {"raw_sha256", "case_entry_sha256"}
_SOURCE_KEYS = {"repository_url", "base_sha", "github_root_tree_oid", "archive", "attestation"}
_ARCHIVE_KEYS = {
    "path",
    "sha256",
    "bytes",
    "extracted_member_count",
    "extracted_file_count",
    "extracted_directory_count",
    "extracted_bytes",
}
_ATTESTATION_KEYS = {
    "algorithm",
    "tree_sha256",
    "reconstructed_git_tree_oid",
    "expected_git_tree_oid",
    "member_count",
    "file_count",
    "directory_count",
    "total_bytes",
    "executable_count",
    "git_metadata_absent",
}
_ACQUISITION_KEYS = {"policy", "policy_sha256", "runtime"}
_POLICY_KEYS = {
    "id",
    "network",
    "archive",
    "extraction",
    "attestation",
}
_RUNTIME_KEYS = {"http_timeout_seconds"}
_TOOL_KEYS = {"name", "version", "git_sha"}

DEFAULT_EXTRACTION_LIMITS = ExtractionLimits()
DEFAULT_ATTESTATION_LIMITS = SourceAttestationLimits()


def source_acquisition_policy(
    *,
    extraction_limits: ExtractionLimits | None = None,
    attestation_limits: SourceAttestationLimits | None = None,
) -> dict[str, object]:
    """Return the concrete, hashable safety policy used for exact-source preparation."""

    extraction = extraction_limits or DEFAULT_EXTRACTION_LIMITS
    attestation = attestation_limits or DEFAULT_ATTESTATION_LIMITS
    return {
        "id": "github-exact-source-v1",
        "network": {
            "scheme": "https",
            "commit_metadata_host": GITHUB_API_HOST,
            "archive_host": GITHUB_CODELOAD_HOST,
            "authentication": "none",
            "proxy_environment": "disabled",
            "redirects": "rejected",
            "tls_minimum": "1.2",
            "commit_metadata_max_bytes": MAX_COMMIT_JSON_BYTES,
        },
        "archive": {
            "source": "codeload_exact_full_40_hex_sha",
            "format": "tar.gz",
            "preserved_filename": SOURCE_ARCHIVE_FILENAME,
            "max_compressed_bytes": MAX_ARCHIVE_BYTES,
        },
        "extraction": {
            "implementation": "manual_streaming_tar_gz_v1",
            "member_types": "regular_files_and_directories_only",
            "links": "reject",
            "special_files": "reject",
            "git_metadata": "reject_nfkc_casefold_rstrip_dot_space",
            "path_collisions": "reject_exact_case_and_unicode_nfc",
            "limits": asdict(extraction),
        },
        "attestation": {
            "algorithm": SOURCE_TREE_ALGORITHM,
            "tree_binding": "reconstructed_oid_equals_fresh_github_root_tree_oid",
            "symlinks": "reject",
            "hardlinks": "reject",
            "special_files": "reject",
            "mount_boundaries": "reject",
            "git_metadata": "reject_nfkc_casefold_rstrip_dot_space",
            "path_collisions": "reject_case_and_unicode_nfc",
            "canonical_file_modes": "100644_or_100755",
            "limits": asdict(attestation),
        },
    }


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _rejection("Value cannot be represented as canonical JSON.") from exc


_SOURCE_ACQUISITION_POLICY = source_acquisition_policy()
SOURCE_ACQUISITION_POLICY_SHA256 = hashlib.sha256(
    _canonical_json_bytes(_SOURCE_ACQUISITION_POLICY)
).hexdigest()


@dataclass(frozen=True)
class FrozenSourceCase:
    id: str
    repository: str
    issue_url: str
    issue_number: int
    base_sha: str
    case_entry_sha256: str

    @property
    def owner(self) -> str:
        return self.repository.split("/", 1)[0]

    @property
    def repo(self) -> str:
        return self.repository.split("/", 1)[1]


@dataclass(frozen=True)
class FrozenSourceManifest:
    path: Path
    raw_sha256: str
    benchmark_version: str
    cases: tuple[FrozenSourceCase, ...]

    def require_case(self, case_id: str) -> FrozenSourceCase:
        matches = [case for case in self.cases if case.id == case_id]
        if len(matches) != 1:
            raise _rejection(f"Manifest does not contain exactly one case {case_id!r}.")
        return matches[0]


def load_frozen_manifest(manifest_path: Path) -> FrozenSourceManifest:
    """Load the bounded, duplicate-key-free 20-case v0.1 public manifest."""

    path = Path(manifest_path)
    raw = _read_bounded_regular(path, MAX_MANIFEST_BYTES, "benchmark manifest")
    decoded = _decode_strict_json(raw, "benchmark manifest")
    root = _exact_object(decoded, _MANIFEST_KEYS, "benchmark manifest")
    _require_equal(root.get("benchmark_version"), BENCHMARK_VERSION, "benchmark version")
    _require_equal(root.get("status"), "preregistered_no_results", "manifest status")
    _require_equal(
        root.get("case_schema"),
        "../../schemas/benchmark-case.schema.json",
        "case schema reference",
    )

    selection = root.get("selection")
    if not isinstance(selection, dict) or selection.get("case_count") != EXPECTED_CASE_COUNT:
        raise _rejection("Manifest selection must freeze exactly 20 cases.")
    cases_value = root.get("cases")
    if not isinstance(cases_value, list) or len(cases_value) != EXPECTED_CASE_COUNT:
        raise _rejection("Manifest must contain exactly 20 cases.")

    cases: list[FrozenSourceCase] = []
    seen_ids: set[str] = set()
    seen_issue_urls: set[str] = set()
    for position, value in enumerate(cases_value, start=1):
        case = _exact_object(value, _CASE_KEYS, f"manifest case {position}")
        case_id = _ascii_pattern(case.get("id"), "case id", _CASE_ID)
        expected_id = f"rk-v0.1-{position:03d}"
        _require_equal(case_id, expected_id, "ordered frozen case id")
        repository = _ascii_pattern(case.get("repo"), "repository", _REPOSITORY)
        issue_url = _bounded_ascii(case.get("issue_url"), "issue URL", 512)
        location = parse_issue_url(issue_url)
        _require_equal(f"{location.owner}/{location.repo}", repository, "issue repository")
        base_sha = _ascii_pattern(case.get("base_sha"), "base SHA", _GIT_SHA)
        difficulty = case.get("difficulty")
        if difficulty not in {"lt_15m", "15m_to_1h"}:
            raise _rejection("Manifest case difficulty is invalid.")
        title = case.get("title")
        if not isinstance(title, str) or not 1 <= len(title) <= 300:
            raise _rejection("Manifest case title is invalid.")
        if not isinstance(case.get("smoke"), bool):
            raise _rejection("Manifest case smoke marker is invalid.")
        if case_id in seen_ids or issue_url in seen_issue_urls:
            raise _rejection("Manifest contains a duplicate case or issue URL.")
        seen_ids.add(case_id)
        seen_issue_urls.add(issue_url)
        cases.append(
            FrozenSourceCase(
                id=case_id,
                repository=repository,
                issue_url=issue_url,
                issue_number=location.number,
                base_sha=base_sha,
                case_entry_sha256=hashlib.sha256(_canonical_json_bytes(case)).hexdigest(),
            )
        )

    smoke_ids = selection.get("smoke_case_ids")
    expected_smoke_ids = [
        cast(str, cast(dict[str, object], value)["id"])
        for value in cases_value
        if cast(dict[str, object], value)["smoke"] is True
    ]
    if smoke_ids != expected_smoke_ids:
        raise _rejection("Manifest smoke case list does not match case entries.")

    raw_sha256 = hashlib.sha256(raw).hexdigest()
    if raw_sha256 != FROZEN_MANIFEST_SHA256:
        raise _rejection("Manifest bytes do not match the frozen v0.1 preregistration.")

    return FrozenSourceManifest(
        path=path,
        raw_sha256=raw_sha256,
        benchmark_version=BENCHMARK_VERSION,
        cases=tuple(cases),
    )


def prepare_source_case(
    manifest_path: Path,
    case_id: str,
    output_root: Path,
    *,
    tool_git_sha: str,
    timeout_seconds: float = 15.0,
) -> Path:
    """Acquire and attest one exact source archive without invoking generation.

    ``output_root`` must be a controller-owned 0700 directory. A new deterministic
    case directory is created beneath it; existing case output is never reused.
    The archive is preserved, the inert extraction is removed, and the receipt is
    written only after every check and cleanup succeeds.
    """

    manifest = load_frozen_manifest(manifest_path)
    case = manifest.require_case(case_id)
    producer_git_sha = _ascii_pattern(tool_git_sha, "tool Git SHA", _GIT_SHA)
    acquisition_timeout = _timeout(timeout_seconds, "acquisition timeout")
    root = Path(output_root)
    require_private_directory(root)
    case_dir = root / case.id
    created = False
    try:
        try:
            case_dir.mkdir(mode=0o700)
            created = True
        except FileExistsError as exc:
            raise PolicyRejection(
                "output_exists", f"Refusing to overwrite source preparation: {case_dir}"
            ) from exc
        os.chmod(case_dir, 0o700, follow_symlinks=False)
        require_private_directory(case_dir)

        commit = fetch_commit_tree_metadata(
            case.owner,
            case.repo,
            case.base_sha,
            timeout_seconds=acquisition_timeout,
        )
        if commit.commit_sha != case.base_sha:
            raise _rejection("Commit metadata does not match the manifest base SHA.")
        archive = download_source_archive(
            case.owner,
            case.repo,
            case.base_sha,
            case_dir,
            timeout_seconds=acquisition_timeout,
        )
        if archive.path != case_dir / SOURCE_ARCHIVE_FILENAME:
            raise _rejection("Archive downloader returned an unexpected path.")
        archive_sha256, archive_bytes = _hash_regular_file(
            archive.path, max_bytes=MAX_ARCHIVE_BYTES
        )
        if archive.sha256 != archive_sha256 or archive.size_bytes != archive_bytes:
            raise _rejection("Archive downloader metadata does not match the saved archive.")

        extracted = extract_source_archive(
            archive.path,
            case_dir,
            limits=DEFAULT_EXTRACTION_LIMITS,
        )
        attestation = attest_source_tree(
            extracted.source_root,
            limits=DEFAULT_ATTESTATION_LIMITS,
            expected_git_tree_oid=commit.tree_sha,
        )
        _reconcile_extraction(extracted, attestation)
        final_archive_sha256, final_archive_bytes = _hash_regular_file(
            archive.path, max_bytes=MAX_ARCHIVE_BYTES
        )
        if (final_archive_sha256, final_archive_bytes) != (archive.sha256, archive.size_bytes):
            raise _rejection("Source archive changed during extraction and attestation.")
        receipt = _build_receipt(
            manifest=manifest,
            case=case,
            commit=commit,
            archive=archive,
            extracted=extracted,
            attestation=attestation,
            acquisition_timeout_seconds=acquisition_timeout,
            tool_version=__version__,
            tool_git_sha=producer_git_sha,
        )

        _remove_extraction(extracted.destination)
        receipt_path = case_dir / SOURCE_RECEIPT_FILENAME
        write_bytes_exclusive(receipt_path, _canonical_json_bytes(receipt) + b"\n")
        return receipt_path
    except BaseException:
        if created:
            shutil.rmtree(case_dir, ignore_errors=True)
        raise


def verify_source_receipt(
    receipt_path: Path,
    *,
    manifest_path: Path,
    expected_case_id: str,
    expected_receipt_sha256: str | None = None,
    scratch_root: Path | None = None,
    timeout_seconds: float = 15.0,
) -> dict[str, object]:
    """Independently rehash, reextract, reattest, and compare a source receipt."""

    manifest = load_frozen_manifest(manifest_path)
    case = manifest.require_case(expected_case_id)
    verification_timeout = _timeout(timeout_seconds, "verification timeout")
    path = Path(receipt_path)
    raw = _read_bounded_regular(path, MAX_RECEIPT_BYTES, "source receipt")
    actual_receipt_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_receipt_sha256 is not None:
        expected_hash = _ascii_pattern(expected_receipt_sha256, "expected receipt SHA-256", _SHA256)
        _require_equal(actual_receipt_sha256, expected_hash, "receipt SHA-256")
    decoded = _decode_strict_json(raw, "source receipt")
    if raw != _canonical_json_bytes(decoded) + b"\n":
        raise _rejection("Source receipt bytes are not canonical JSON with one final newline.")
    receipt = _validate_receipt_shape(decoded)
    _validate_receipt_manifest_binding(receipt, manifest, case)

    source = cast(dict[str, object], receipt["source"])
    archive_record = cast(dict[str, object], source["archive"])
    archive_relative = _require_archive_relative_path(archive_record.get("path"))
    archive_path = path.parent / archive_relative
    trusted_commit = fetch_commit_tree_metadata(
        case.owner,
        case.repo,
        case.base_sha,
        timeout_seconds=verification_timeout,
    )
    if trusted_commit.commit_sha != case.base_sha:
        raise _rejection("Fresh commit metadata does not match the manifest base SHA.")
    receipt_tree_oid = _ascii_pattern(
        source.get("github_root_tree_oid"), "GitHub root tree OID", _GIT_SHA
    )
    if receipt_tree_oid != trusted_commit.tree_sha:
        raise _rejection("Receipt tree OID does not match fresh GitHub commit metadata.")

    scratch = _allocate_scratch(scratch_root)
    try:
        staged_archive = _stage_regular_file(
            archive_path,
            scratch / SOURCE_ARCHIVE_FILENAME,
            max_bytes=MAX_ARCHIVE_BYTES,
        )
        extracted = extract_source_archive(
            staged_archive.path,
            scratch,
            limits=DEFAULT_EXTRACTION_LIMITS,
        )
        attestation = attest_source_tree(
            extracted.source_root,
            limits=DEFAULT_ATTESTATION_LIMITS,
            expected_git_tree_oid=trusted_commit.tree_sha,
        )
        _reconcile_extraction(extracted, attestation)
        acquisition = cast(dict[str, object], receipt["acquisition"])
        runtime = cast(dict[str, object], acquisition["runtime"])
        tool = cast(dict[str, object], receipt["tool"])
        expected = _build_receipt(
            manifest=manifest,
            case=case,
            commit=trusted_commit,
            archive=staged_archive,
            extracted=extracted,
            attestation=attestation,
            acquisition_timeout_seconds=cast(float, runtime["http_timeout_seconds"]),
            tool_version=cast(str, tool["version"]),
            tool_git_sha=cast(str, tool["git_sha"]),
        )
        if receipt != expected:
            raise _rejection("Source receipt fields do not match independently derived values.")
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    _remove_scratch_checked(scratch)
    return receipt


def build_source_index(
    manifest_path: Path,
    receipts_root: Path,
    receipt_paths: Sequence[str | Path],
    output_path: Path,
    *,
    tool_git_sha: str,
    scratch_root: Path | None = None,
    timeout_seconds: float = 15.0,
) -> Path:
    """Verify exactly 20 frozen receipts and write a deterministic inert index.

    Receipt paths are relative to ``receipts_root`` and must be exactly
    ``<case-id>/benchmark-source-receipt.json``. The resulting index contains no
    campaign, attempt-ledger, or readiness state.
    """

    manifest = load_frozen_manifest(manifest_path)
    index_tool_git_sha = _ascii_pattern(tool_git_sha, "index tool Git SHA", _GIT_SHA)
    verification_timeout = _timeout(timeout_seconds, "index verification timeout")
    root = Path(receipts_root)
    require_private_directory(root)
    if len(receipt_paths) != len(manifest.cases):
        raise _rejection("Source index requires exactly the manifest's 20 receipts.")

    by_case: dict[str, Path] = {}
    for value in receipt_paths:
        relative = _validate_receipt_relative_path(value)
        case_id = relative.parts[0]
        if case_id in by_case:
            raise _rejection("Source index contains a duplicate receipt case.")
        by_case[case_id] = relative
    expected_ids = {case.id for case in manifest.cases}
    if set(by_case) != expected_ids:
        raise _rejection("Source index receipts do not exactly match the frozen manifest.")

    entries: list[dict[str, object]] = []
    observed_policy_hashes: set[str] = set()
    observed_manifest_hashes: set[str] = set()
    observed_producers: set[tuple[str, str]] = set()
    for case in manifest.cases:
        relative = by_case[case.id]
        receipt_path = root / relative
        receipt_sha256, receipt_bytes = _hash_regular_file(
            receipt_path, max_bytes=MAX_RECEIPT_BYTES
        )
        receipt = verify_source_receipt(
            receipt_path,
            manifest_path=manifest_path,
            expected_case_id=case.id,
            expected_receipt_sha256=receipt_sha256,
            scratch_root=scratch_root,
            timeout_seconds=verification_timeout,
        )
        final_receipt_sha256, final_receipt_bytes = _hash_regular_file(
            receipt_path, max_bytes=MAX_RECEIPT_BYTES
        )
        if (final_receipt_sha256, final_receipt_bytes) != (receipt_sha256, receipt_bytes):
            raise _rejection("Source receipt changed during index verification.")
        manifest_record = cast(dict[str, object], receipt["manifest"])
        acquisition = cast(dict[str, object], receipt["acquisition"])
        receipt_tool = cast(dict[str, object], receipt["tool"])
        source = cast(dict[str, object], receipt["source"])
        archive = cast(dict[str, object], source["archive"])
        attestation = cast(dict[str, object], source["attestation"])
        observed_manifest_hashes.add(cast(str, manifest_record["raw_sha256"]))
        observed_policy_hashes.add(cast(str, acquisition["policy_sha256"]))
        observed_producers.add(
            (cast(str, receipt_tool["version"]), cast(str, receipt_tool["git_sha"]))
        )
        entries.append(
            {
                "case_id": case.id,
                "path": relative.as_posix(),
                "sha256": receipt_sha256,
                "bytes": receipt_bytes,
                "archive_sha256": archive["sha256"],
                "source_tree_sha256": attestation["tree_sha256"],
                "git_tree_oid": source["github_root_tree_oid"],
            }
        )
    if observed_manifest_hashes != {manifest.raw_sha256}:
        raise _rejection("Source receipts mix manifest identities.")
    if observed_policy_hashes != {SOURCE_ACQUISITION_POLICY_SHA256}:
        raise _rejection("Source receipts mix acquisition policies.")
    if len(observed_producers) != 1:
        raise _rejection("Source receipts mix producer tool provenance.")

    index: dict[str, object] = {
        "schema_version": SOURCE_INDEX_SCHEMA_VERSION,
        "benchmark_version": manifest.benchmark_version,
        "manifest": {
            "raw_sha256": manifest.raw_sha256,
            "case_count": len(manifest.cases),
        },
        "acquisition_policy_sha256": SOURCE_ACQUISITION_POLICY_SHA256,
        "receipt_count": len(entries),
        "receipts": entries,
        "tool": {
            "name": "reproassert",
            "version": __version__,
            "git_sha": index_tool_git_sha,
        },
    }
    destination = Path(output_path)
    write_bytes_exclusive(destination, _canonical_json_bytes(index) + b"\n")
    return destination


def _build_receipt(
    *,
    manifest: FrozenSourceManifest,
    case: FrozenSourceCase,
    commit: CommitTreeMetadata,
    archive: ArchiveDownload,
    extracted: ExtractedArchive,
    attestation: SourceTreeAttestation,
    acquisition_timeout_seconds: float,
    tool_version: str,
    tool_git_sha: str,
) -> dict[str, object]:
    return {
        "schema_version": SOURCE_RECEIPT_SCHEMA_VERSION,
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
            "archive": {
                "path": SOURCE_ARCHIVE_FILENAME,
                "sha256": archive.sha256,
                "bytes": archive.size_bytes,
                "extracted_member_count": extracted.member_count,
                "extracted_file_count": extracted.file_count,
                "extracted_directory_count": extracted.directory_count,
                "extracted_bytes": extracted.unpacked_bytes,
            },
            "attestation": {
                "algorithm": attestation.algorithm,
                "tree_sha256": attestation.tree_sha256,
                "reconstructed_git_tree_oid": attestation.reconstructed_git_tree_oid,
                "expected_git_tree_oid": attestation.expected_git_tree_oid,
                "member_count": attestation.member_count,
                "file_count": attestation.file_count,
                "directory_count": attestation.directory_count,
                "total_bytes": attestation.total_bytes,
                "executable_count": attestation.executable_count,
                "git_metadata_absent": attestation.git_metadata_absent,
            },
        },
        "acquisition": {
            "policy": source_acquisition_policy(),
            "policy_sha256": SOURCE_ACQUISITION_POLICY_SHA256,
            "runtime": {"http_timeout_seconds": acquisition_timeout_seconds},
        },
        "tool": {"name": "reproassert", "version": tool_version, "git_sha": tool_git_sha},
    }


def _validate_receipt_shape(value: object) -> dict[str, object]:
    root = _exact_object(value, _RECEIPT_KEYS, "source receipt")
    _require_equal(root.get("schema_version"), SOURCE_RECEIPT_SCHEMA_VERSION, "schema version")
    _require_equal(root.get("benchmark_version"), BENCHMARK_VERSION, "benchmark version")
    case = _exact_object(root.get("case"), _RECEIPT_CASE_KEYS, "receipt case")
    _ascii_pattern(case.get("id"), "receipt case id", _CASE_ID)
    _ascii_pattern(case.get("repository"), "receipt repository", _REPOSITORY)
    _bounded_ascii(case.get("issue_url"), "receipt issue URL", 512)
    _nonnegative_integer(case.get("issue_number"), "receipt issue number", positive=True)
    _ascii_pattern(case.get("base_sha"), "receipt base SHA", _GIT_SHA)

    manifest = _exact_object(root.get("manifest"), _RECEIPT_MANIFEST_KEYS, "receipt manifest")
    _ascii_pattern(manifest.get("raw_sha256"), "manifest SHA-256", _SHA256)
    _ascii_pattern(manifest.get("case_entry_sha256"), "case entry SHA-256", _SHA256)

    source = _exact_object(root.get("source"), _SOURCE_KEYS, "receipt source")
    _bounded_ascii(source.get("repository_url"), "repository URL", 512)
    _ascii_pattern(source.get("base_sha"), "source base SHA", _GIT_SHA)
    _ascii_pattern(source.get("github_root_tree_oid"), "GitHub root tree OID", _GIT_SHA)
    archive = _exact_object(source.get("archive"), _ARCHIVE_KEYS, "source archive")
    _require_archive_relative_path(archive.get("path"))
    _ascii_pattern(archive.get("sha256"), "archive SHA-256", _SHA256)
    for name in _ARCHIVE_KEYS - {"path", "sha256"}:
        _nonnegative_integer(archive.get(name), f"archive {name}")
    attestation = _exact_object(source.get("attestation"), _ATTESTATION_KEYS, "source attestation")
    _bounded_ascii(attestation.get("algorithm"), "attestation algorithm", 128)
    _ascii_pattern(attestation.get("tree_sha256"), "source tree SHA-256", _SHA256)
    _ascii_pattern(
        attestation.get("reconstructed_git_tree_oid"), "reconstructed Git tree OID", _GIT_SHA
    )
    _ascii_pattern(attestation.get("expected_git_tree_oid"), "expected Git tree OID", _GIT_SHA)
    for name in {
        "member_count",
        "file_count",
        "directory_count",
        "total_bytes",
        "executable_count",
    }:
        _nonnegative_integer(attestation.get(name), f"attestation {name}")
    if attestation.get("git_metadata_absent") is not True:
        raise _rejection("Source receipt must attest that Git metadata is absent.")

    acquisition = _exact_object(root.get("acquisition"), _ACQUISITION_KEYS, "source acquisition")
    policy = _exact_object(acquisition.get("policy"), _POLICY_KEYS, "acquisition policy")
    if policy != _SOURCE_ACQUISITION_POLICY:
        raise _rejection("Source receipt acquisition policy is not the frozen policy.")
    _require_equal(
        acquisition.get("policy_sha256"),
        SOURCE_ACQUISITION_POLICY_SHA256,
        "acquisition policy SHA-256",
    )
    runtime = _exact_object(acquisition.get("runtime"), _RUNTIME_KEYS, "acquisition runtime")
    _timeout(runtime.get("http_timeout_seconds"), "recorded HTTP timeout")
    tool = _exact_object(root.get("tool"), _TOOL_KEYS, "receipt tool")
    _require_equal(tool.get("name"), "reproassert", "tool name")
    _ascii_pattern(tool.get("version"), "tool version", _VERSION)
    _ascii_pattern(tool.get("git_sha"), "tool Git SHA", _GIT_SHA)
    return root


def _validate_receipt_manifest_binding(
    receipt: Mapping[str, object],
    manifest: FrozenSourceManifest,
    case: FrozenSourceCase,
) -> None:
    case_record = cast(dict[str, object], receipt["case"])
    expected_case: dict[str, object] = {
        "id": case.id,
        "repository": case.repository,
        "issue_url": case.issue_url,
        "issue_number": case.issue_number,
        "base_sha": case.base_sha,
    }
    if case_record != expected_case:
        raise _rejection("Source receipt does not match the requested manifest case.")
    manifest_record = cast(dict[str, object], receipt["manifest"])
    expected_manifest = {
        "raw_sha256": manifest.raw_sha256,
        "case_entry_sha256": case.case_entry_sha256,
    }
    if manifest_record != expected_manifest:
        raise _rejection("Source receipt does not match the frozen manifest bytes.")


def _reconcile_extraction(extracted: ExtractedArchive, attestation: SourceTreeAttestation) -> None:
    if extracted.file_count != attestation.file_count:
        raise _rejection("Extraction and attestation file counts differ.")
    if extracted.unpacked_bytes != attestation.total_bytes:
        raise _rejection("Extraction and attestation byte counts differ.")


def _remove_extraction(destination: Path) -> None:
    shutil.rmtree(destination)
    if destination.exists() or destination.is_symlink():
        raise _rejection("Unable to clean the temporary source extraction.")


def _remove_scratch_checked(scratch: Path) -> None:
    try:
        shutil.rmtree(scratch)
    except OSError as exc:
        raise _rejection("Unable to clean the private verification scratch directory.") from exc
    if scratch.exists() or scratch.is_symlink():
        raise _rejection("Unable to clean the private verification scratch directory.")


def _allocate_scratch(scratch_root: Path | None) -> Path:
    if scratch_root is None:
        # macOS exposes /var as a symlink to /private/var. Resolve the newly
        # allocated directory before passing it to the no-follow path walker.
        scratch = Path(tempfile.mkdtemp(prefix="reproassert-source-verify-")).resolve(strict=True)
        os.chmod(scratch, 0o700, follow_symlinks=False)
        require_private_directory(scratch)
        return scratch
    base = Path(scratch_root)
    require_private_directory(base)
    return create_private_run_dir(base, prefix="source-verify-")


def _stage_regular_file(source: Path, destination: Path, *, max_bytes: int) -> ArchiveDownload:
    """Copy one stable regular-file snapshot into a new private scratch file."""

    created = False
    try:
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise _rejection(f"Required input is not a regular file: {source.name}.")
        if before.st_size > max_bytes:
            raise _rejection(f"Required regular file exceeds the byte limit: {source.name}.")
        with open_regular_file(source) as input_stream:
            opened = os.fstat(input_stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise _rejection(f"Required regular file changed before reading: {source.name}.")
            digest = hashlib.sha256()
            total = 0
            with open_exclusive_file(destination) as output_stream:
                created = True
                while True:
                    chunk = input_stream.read(min(64 * 1024, max_bytes - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise _rejection(
                            f"Required regular file exceeds the byte limit: {source.name}."
                        )
                    digest.update(chunk)
                    output_stream.write(chunk)
                output_stream.flush()
                os.fsync(output_stream.fileno())
            after = os.fstat(input_stream.fileno())
            if _file_changed(opened, after) or total != after.st_size:
                raise _rejection(f"Required regular file changed while reading: {source.name}.")
        return ArchiveDownload(path=destination, sha256=digest.hexdigest(), size_bytes=total)
    except (OSError, PolicyRejection) as exc:
        if created:
            destination.unlink(missing_ok=True)
        if isinstance(exc, PolicyRejection) and exc.code == "benchmark_source_receipt":
            raise
        raise _rejection(f"Required regular file is unavailable: {source.name}.") from exc


def _validate_receipt_relative_path(value: str | Path) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise _rejection("Receipt index path is invalid.")
    relative = Path(raw)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise _rejection("Receipt index paths must be safe relative paths.")
    if len(relative.parts) != 2 or relative.name != SOURCE_RECEIPT_FILENAME:
        raise _rejection("Receipt index path must use the frozen case layout.")
    _ascii_pattern(relative.parts[0], "receipt path case id", _CASE_ID)
    if relative.as_posix() != raw:
        raise _rejection("Receipt index paths must be canonical relative paths.")
    return relative


def _require_archive_relative_path(value: object) -> Path:
    if value != SOURCE_ARCHIVE_FILENAME:
        raise _rejection("Source archive path must be the frozen relative filename.")
    return Path(SOURCE_ARCHIVE_FILENAME)


def _hash_regular_file(path: Path, *, max_bytes: int | None = None) -> tuple[str, int]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise _rejection(f"Required input is not a regular file: {path.name}.")
        if max_bytes is not None and before.st_size > max_bytes:
            raise _rejection(f"Required regular file exceeds the byte limit: {path.name}.")
        with open_regular_file(path) as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise _rejection(f"Required regular file changed before reading: {path.name}.")
            if max_bytes is not None and opened.st_size > max_bytes:
                raise _rejection(f"Required regular file exceeds the byte limit: {path.name}.")
            digest = hashlib.sha256()
            total = 0
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    raise _rejection(f"Required regular file exceeds the byte limit: {path.name}.")
                digest.update(chunk)
            after = os.fstat(stream.fileno())
            if _file_changed(opened, after) or total != after.st_size:
                raise _rejection(f"Required regular file changed while reading: {path.name}.")
    except (OSError, PolicyRejection) as exc:
        raise _rejection(f"Required regular file is unavailable: {path.name}.") from exc
    return digest.hexdigest(), total


def _read_bounded_regular(path: Path, limit: int, label: str) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise _rejection(f"Unable to read {label} as a regular file.")
        if before.st_size > limit:
            raise _rejection(f"{label.capitalize()} exceeds the byte limit.")
        with open_regular_file(path) as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise _rejection(f"{label.capitalize()} changed before reading.")
            if opened.st_size > limit:
                raise _rejection(f"{label.capitalize()} exceeds the byte limit.")
            content = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if _file_changed(opened, after) or len(content) != after.st_size:
                raise _rejection(f"{label.capitalize()} changed while reading.")
    except (OSError, PolicyRejection) as exc:
        if isinstance(exc, PolicyRejection) and exc.code == "benchmark_source_receipt":
            raise
        raise _rejection(f"Unable to read {label} as a regular file.") from exc
    if len(content) > limit:
        raise _rejection(f"{label.capitalize()} exceeds the byte limit.")
    return content


def _file_changed(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    )


def _decode_strict_json(raw: bytes, label: str) -> object:
    try:
        text = raw.decode("utf-8")
        _reject_excessive_json_nesting(text)
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _rejection(f"{label.capitalize()} is not strict UTF-8 JSON.") from exc


def _reject_excessive_json_nesting(text: str) -> None:
    """Bound container depth before CPython's version-dependent JSON parser runs."""

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING:
                raise ValueError("JSON nesting exceeds the controller limit")
        elif character in "]}":
            depth -= 1


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _rejection(f"{label.capitalize()} fields do not match the frozen contract.")
    if not all(isinstance(key, str) for key in value):
        raise _rejection(f"{label.capitalize()} contains a non-string field name.")
    return cast(dict[str, object], value)


def _ascii_pattern(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not value.isascii() or pattern.fullmatch(value) is None:
        raise _rejection(f"{label.capitalize()} is invalid.")
    return value


def _bounded_ascii(value: object, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not 1 <= len(value.encode("ascii")) <= maximum
    ):
        raise _rejection(f"{label.capitalize()} is invalid.")
    return value


def _timeout(value: object, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0 < float(value) <= MAX_HTTP_TIMEOUT_SECONDS
    ):
        raise _rejection(
            f"{label.capitalize()} must be between 0 and {MAX_HTTP_TIMEOUT_SECONDS:g} seconds."
        )
    return float(value)


def _nonnegative_integer(value: object, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= 2**63 - 1:
        raise _rejection(f"{label.capitalize()} is invalid.")
    return value


def _require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected or type(actual) is not type(expected):
        raise _rejection(f"Unexpected {label}.")


def _rejection(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_source_receipt", message)
