"""Evaluator-private, offline evidence preparation for the frozen v0.2 source dataset.

This module is not an untrusted-code sandbox. The exact hash-locked Parquet bytes, fixed worker,
dedicated interpreter, and native pyarrow 24.0.0 build form part of the evidence-preparation TCB.
The child receives no inherited environment, stdin, repository paths, or credentials and has
CPU/output/time limits, but host-native parser vulnerabilities remain a documented residual risk.
macOS cannot enforce a useful native-process memory rlimit for this PyArrow build. Production
hosted parsing must place the same worker inside a memory-bounded, no-secret, network-disabled
container or microVM boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from reproassert.benchmark_v02_package import SOURCE_DATASET_TRANSFORM, V02CaseIdentity
from reproassert.benchmark_v02_upstream import (
    VerifiedV02UpstreamProvenance,
    require_v02_upstream_provenance,
    verify_v02_upstream_provenance,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_exclusive_file, open_regular_file, write_bytes_exclusive
from reproassert.semantic_issuer import (
    OFFICIAL_SOURCE_DATASET_BYTES,
    OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID,
    OFFICIAL_SOURCE_DATASET_GIT_SHA,
    OFFICIAL_SOURCE_DATASET_LFS_SHA256,
    OFFICIAL_SOURCE_DATASET_PATH,
    OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID,
    OFFICIAL_SOURCE_DATASET_XET_SHA256,
    OFFICIAL_TDD_BENCH_GIT_SHA,
    OFFICIAL_TDD_BENCH_ROOT_TREE_OID,
    OFFICIAL_TDD_ID_LIST_BLOB_OID,
    OFFICIAL_TDD_ID_LIST_BYTES,
    OFFICIAL_TDD_ID_LIST_PATH,
    OFFICIAL_TDD_ID_LIST_SHA256,
)

DATASET_PARSER_RECEIPT_ALGORITHM = "reproassert-v02-offline-dataset-parser-receipt-v1"
PUBLIC_DATASET_PROVENANCE_ALGORITHM = "reproassert-v02-public-dataset-provenance-v1"
PYARROW_VERSION = "24.0.0"
PARSER_PROTOCOL = "reproassert-v02-pyarrow-worker-v1"
PROJECTION_REQUEST_PROTOCOL = "reproassert-v02-dataset-projection-request-v1"
TDD_BENCH_REPOSITORY_URL = "https://github.com/IBM/TDD-Bench-Verified"
SOURCE_DATASET_REPOSITORY_URL = "https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified"
SOURCE_DATASET_SPLIT = "test"
SOURCE_DATASET_LFS_POINTER_SHA256 = (
    "b12493d10f165a9107deccbf03b5e4f3f14df2f5727da09629c779c4ea6b1643"
)
EXPECTED_SOURCE_ROWS = 500
EXPECTED_SOURCE_COLUMNS = 13
EXPECTED_TDD_MEMBERS = 449
_MAX_RECEIPT_BYTES = 2 * 1024 * 1024
_MAX_WORKER_BYTES = 128 * 1024
_MAX_WORKER_OUTPUT_BYTES = 2 * 1024 * 1024
_WORKER_TIMEOUT_SECONDS = 60
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_INSTANCE_ID = re.compile(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[1-9][0-9]*\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_WORKER_RESULT_KEYS = {
    "all_rows_commitment_sha256",
    "column_count",
    "columns",
    "issue_projections",
    "leak_audit_rows",
    "parquet_created_by",
    "pyarrow_version",
    "row_count",
    "row_group_count",
    "rows",
    "schema_sha256",
    "unique_instance_id_count",
}
_ROW_KEYS = {"identity_sha256", "instance_id", "row_ordinal", "row_sha256"}
_LEAK_AUDIT_KEYS = {
    "base_commit",
    "direct_own_fixing_pr_reference",
    "difficulty",
    "instance_id",
    "issue_text_bytes",
    "issue_text_sha256",
    "oracle_leak_free",
    "production_added_line_overlap",
    "repo",
    "row_ordinal",
    "test_added_line_overlap",
}
_ISSUE_PROJECTION_KEYS = {"instance_id", "problem_statement"}
_JOINED_ROW_KEYS = {
    "identity_sha256",
    "instance_id",
    "source_dataset_row_ordinal",
    "source_dataset_row_sha256",
    "tdd_membership_ordinal",
}
_COLUMNS = (
    "repo",
    "instance_id",
    "base_commit",
    "patch",
    "test_patch",
    "problem_statement",
    "hints_text",
    "created_at",
    "version",
    "FAIL_TO_PASS",
    "PASS_TO_PASS",
    "environment_setup_commit",
    "difficulty",
)


@dataclass(frozen=True)
class PreparedV02DatasetEvidence:
    """Host-native preparation evidence that is deliberately ineligible for production use."""

    case: V02CaseIdentity
    instance_id: str
    tdd_membership_ordinal: int
    source_dataset_row_ordinal: int
    source_dataset_row_sha256: str
    parser_receipt_sha256: str
    upstream_evidence_sha256: str
    production_eligible: bool = False


def render_private_v02_dataset_parser_receipt(
    *,
    tdd_id_list_path: Path,
    source_dataset_path: Path,
    upstream_object_witness_path: Path,
    parser_python: Path,
    projection_instance_ids: tuple[str, ...] = (),
) -> bytes:
    """Rederive the private commitment-only receipt from the two pinned upstream artifacts.

    The returned receipt contains instance IDs, ordinals, and hashes, but none of the hidden row
    fields. It remains evaluator-private because even membership/ordering is preregistered evidence.
    `parser_python` must be a trusted dedicated venv containing exactly pyarrow 24.0.0.
    """

    return _derive_receipt(
        tdd_id_list_path=Path(tdd_id_list_path),
        source_dataset_path=Path(source_dataset_path),
        upstream_object_witness_path=Path(upstream_object_witness_path),
        parser_python=Path(parser_python),
        projection_instance_ids=projection_instance_ids,
    )


def render_public_v02_dataset_provenance_record(
    private_receipt_path: Path,
    *,
    upstream_object_witness_path: Path,
    tdd_id_list_path: Path,
    source_dataset_path: Path,
) -> bytes:
    """Project a private parser receipt into aggregate, oracle-safe public evidence.

    The projection intentionally excludes instance IDs, row ordinals, row commitments, and every
    upstream row field (including production patches and developer tests). The upstream artifact
    identities are public immutable provenance, while the aggregate shape checks are safe to
    publish after the cohort freeze.
    """

    content = _read_bounded_regular(
        Path(private_receipt_path), _MAX_RECEIPT_BYTES, "private dataset parser receipt"
    )
    receipt = _validate_private_receipt(content)
    verified_upstream = verify_v02_upstream_provenance(
        upstream_object_witness_path,
        tdd_id_list_path=tdd_id_list_path,
        source_dataset_path=source_dataset_path,
    )
    _cross_bind_upstream(receipt, verified_upstream)
    dataset = cast(dict[str, object], receipt["dataset"])
    parser = cast(dict[str, object], receipt["parser"])
    upstream = cast(dict[str, object], receipt["upstream"])
    record: dict[str, object] = {
        "algorithm": PUBLIC_DATASET_PROVENANCE_ALGORITHM,
        "dataset_checks": {
            "column_count": dataset["column_count"],
            "joined_tdd_row_count": dataset["joined_tdd_row_count"],
            "row_count": dataset["row_count"],
            "row_group_count": dataset["row_group_count"],
            "source_dataset_transform": dataset["source_dataset_transform"],
            "unique_instance_id_count": dataset["unique_instance_id_count"],
        },
        "parser": {
            "parser_protocol": parser["parser_protocol"],
            "pyarrow_version": parser["pyarrow_version"],
            "trusted_worker_sha256": parser["trusted_worker_sha256"],
        },
        "security": {
            "host_native_parser_residual_risk": True,
            "macos_host_native_memory_limit_enforced": False,
            "production_use": "evidence_preparation_only",
            "real_sandbox_required_for_memory_and_untrusted_inputs": True,
        },
        "upstream": upstream,
    }
    return _canonical(record) + b"\n"


def prepare_v02_dataset_evidence(
    receipt_path: Path,
    *,
    case: V02CaseIdentity,
    instance_id: str,
    tdd_id_list_path: Path,
    source_dataset_path: Path,
    upstream_object_witness_path: Path,
    parser_python: Path,
    projection_instance_ids: tuple[str, ...] = (),
) -> PreparedV02DatasetEvidence:
    """Freshly rederive host-native preparation evidence without minting a live capability."""

    if not isinstance(instance_id, str) or _INSTANCE_ID.fullmatch(instance_id) is None:
        raise _reject("Dataset instance ID is invalid.")
    before = _read_bounded_regular(
        Path(receipt_path), _MAX_RECEIPT_BYTES, "private dataset parser receipt"
    )
    expected = _derive_receipt(
        tdd_id_list_path=Path(tdd_id_list_path),
        source_dataset_path=Path(source_dataset_path),
        upstream_object_witness_path=Path(upstream_object_witness_path),
        parser_python=Path(parser_python),
        projection_instance_ids=projection_instance_ids,
    )
    if before != expected:
        raise _reject("Dataset parser receipt differs from fresh pinned-artifact derivation.")
    after = _read_bounded_regular(
        Path(receipt_path), _MAX_RECEIPT_BYTES, "private dataset parser receipt"
    )
    if after != before:
        raise _reject("Dataset parser receipt changed during verification.")
    decoded = _decode_canonical_receipt(before)
    joined = cast(list[object], cast(dict[str, object], decoded["dataset"])["joined_tdd_rows"])
    selected = next(
        (
            cast(dict[str, object], item)
            for item in joined
            if isinstance(item, dict) and item.get("instance_id") == instance_id
        ),
        None,
    )
    if selected is None:
        raise _reject("Dataset instance is not a member of the exact TDD-Bench cohort.")
    identity = {
        "base_commit": case.base_sha,
        "instance_id": instance_id,
        "repo": case.repo,
    }
    if selected["identity_sha256"] != hashlib.sha256(_canonical(identity)).hexdigest():
        raise _reject("Dataset row identity differs from the requested benchmark case.")
    upstream = verify_v02_upstream_provenance(
        upstream_object_witness_path,
        tdd_id_list_path=tdd_id_list_path,
        source_dataset_path=source_dataset_path,
    )
    return PreparedV02DatasetEvidence(
        case=case,
        instance_id=instance_id,
        tdd_membership_ordinal=cast(int, selected["tdd_membership_ordinal"]),
        source_dataset_row_ordinal=cast(int, selected["source_dataset_row_ordinal"]),
        source_dataset_row_sha256=cast(str, selected["source_dataset_row_sha256"]),
        parser_receipt_sha256=hashlib.sha256(before).hexdigest(),
        upstream_evidence_sha256=upstream.evidence_sha256,
    )


def _derive_receipt(
    *,
    tdd_id_list_path: Path,
    source_dataset_path: Path,
    upstream_object_witness_path: Path,
    parser_python: Path,
    projection_instance_ids: tuple[str, ...],
) -> bytes:
    id_list = _read_bounded_regular(
        tdd_id_list_path, OFFICIAL_TDD_ID_LIST_BYTES, "pinned TDD-Bench id list"
    )
    parquet = _read_bounded_regular(
        source_dataset_path, OFFICIAL_SOURCE_DATASET_BYTES, "pinned source dataset"
    )
    _verify_tdd_bytes(id_list)
    _verify_parquet_bytes(parquet)
    upstream_evidence = verify_v02_upstream_provenance(
        upstream_object_witness_path,
        tdd_id_list_path=tdd_id_list_path,
        source_dataset_path=source_dataset_path,
    )
    worker_source = _read_bounded_regular(
        Path(__file__).with_name("_benchmark_v02_parquet_worker.py"),
        _MAX_WORKER_BYTES,
        "trusted Parquet worker",
    )
    worker = _run_worker(
        parser_python,
        worker_source,
        parquet,
        projection_instance_ids=projection_instance_ids,
    )
    return _assemble_receipt(
        id_list=id_list,
        parquet=parquet,
        upstream_evidence=upstream_evidence,
        worker_source=worker_source,
        worker=worker,
    )


def _assemble_receipt(
    *,
    id_list: bytes,
    parquet: bytes,
    upstream_evidence: VerifiedV02UpstreamProvenance,
    worker_source: bytes,
    worker: dict[str, object],
) -> bytes:
    """Trusted-controller receipt assembler shared by native prep and the Docker boundary."""

    require_v02_upstream_provenance(upstream_evidence)
    tdd_members = _verify_tdd_bytes(id_list)
    _verify_parquet_bytes(parquet)
    rows = _validate_worker_result(worker)
    row_by_id = {cast(str, row["instance_id"]): row for row in rows}
    joined: list[dict[str, object]] = []
    for membership_ordinal, instance_id in enumerate(tdd_members, start=1):
        row = row_by_id.get(instance_id)
        if row is None:
            raise _reject("TDD-Bench and source dataset do not have an exact 449-row join.")
        joined.append(
            {
                "identity_sha256": row["identity_sha256"],
                "instance_id": instance_id,
                "source_dataset_row_ordinal": row["row_ordinal"],
                "source_dataset_row_sha256": row["row_sha256"],
                "tdd_membership_ordinal": membership_ordinal,
            }
        )
    if len(joined) != EXPECTED_TDD_MEMBERS or len({item["instance_id"] for item in joined}) != len(
        joined
    ):
        raise _reject("TDD-Bench and source dataset do not have an exact one-to-one join.")
    pointer = _canonical_lfs_pointer()
    record: dict[str, object] = {
        "algorithm": DATASET_PARSER_RECEIPT_ALGORITHM,
        "dataset": {
            "all_rows_commitment_sha256": worker["all_rows_commitment_sha256"],
            "column_count": EXPECTED_SOURCE_COLUMNS,
            "columns": list(_COLUMNS),
            "issue_projections": worker["issue_projections"],
            "issue_projections_sha256": hashlib.sha256(
                _canonical(worker["issue_projections"])
            ).hexdigest(),
            "joined_tdd_row_count": len(joined),
            "joined_tdd_rows": joined,
            "joined_tdd_rows_sha256": hashlib.sha256(_canonical(joined)).hexdigest(),
            "leak_audit_rows": worker["leak_audit_rows"],
            "leak_audit_rows_sha256": hashlib.sha256(
                _canonical(worker["leak_audit_rows"])
            ).hexdigest(),
            "parquet_created_by": worker["parquet_created_by"],
            "row_count": EXPECTED_SOURCE_ROWS,
            "row_group_count": worker["row_group_count"],
            "schema_sha256": worker["schema_sha256"],
            "source_dataset_transform": SOURCE_DATASET_TRANSFORM,
            "unique_instance_id_count": EXPECTED_SOURCE_ROWS,
        },
        "parser": {
            "parser_protocol": PARSER_PROTOCOL,
            "pyarrow_version": PYARROW_VERSION,
            "trusted_worker_sha256": hashlib.sha256(worker_source).hexdigest(),
        },
        "upstream": {
            "source_dataset": {
                "artifact_bytes": upstream_evidence.source_dataset_artifact_lfs_bytes,
                "artifact_git_blob_oid": (upstream_evidence.source_dataset_artifact_git_blob_oid),
                "artifact_lfs_sha256": (upstream_evidence.source_dataset_artifact_lfs_sha256),
                "artifact_path": OFFICIAL_SOURCE_DATASET_PATH,
                "artifact_sha256": hashlib.sha256(parquet).hexdigest(),
                "artifact_xet_sha256": (upstream_evidence.source_dataset_artifact_xet_sha256),
                "git_sha": upstream_evidence.source_dataset_git_sha,
                "lfs_pointer_bytes": len(pointer),
                "lfs_pointer_sha256": hashlib.sha256(pointer).hexdigest(),
                "repository_url": SOURCE_DATASET_REPOSITORY_URL,
                "root_tree_oid": upstream_evidence.source_dataset_root_tree_oid,
                "split": SOURCE_DATASET_SPLIT,
            },
            "tdd_bench": {
                "git_sha": upstream_evidence.tdd_bench_git_sha,
                "id_list_blob_oid": upstream_evidence.tdd_id_list_blob_oid,
                "id_list_bytes": OFFICIAL_TDD_ID_LIST_BYTES,
                "id_list_path": OFFICIAL_TDD_ID_LIST_PATH,
                "id_list_sha256": hashlib.sha256(id_list).hexdigest(),
                "member_count": len(tdd_members),
                "repository_url": TDD_BENCH_REPOSITORY_URL,
                "root_tree_oid": upstream_evidence.tdd_bench_root_tree_oid,
            },
            "verification": {
                "git_graph_verified": upstream_evidence.git_graph_verified,
                "lfs_artifact_verified": upstream_evidence.lfs_artifact_verified,
                "object_witness_sha256": upstream_evidence.witness_sha256,
                "upstream_evidence_sha256": upstream_evidence.evidence_sha256,
                "xet_resolution_cross_bound": upstream_evidence.xet_resolution_cross_bound,
                "xet_resolution_transferable_cryptographic_proof": (
                    upstream_evidence.xet_resolution_transferable_cryptographic_proof
                ),
                "xet_resolution_transport": upstream_evidence.xet_resolution_transport,
            },
        },
    }
    return _canonical(record) + b"\n"


def _verify_tdd_bytes(content: bytes) -> tuple[str, ...]:
    if len(content) != OFFICIAL_TDD_ID_LIST_BYTES:
        raise _reject("TDD-Bench id-list byte count differs from the pinned object.")
    if hashlib.sha256(content).hexdigest() != OFFICIAL_TDD_ID_LIST_SHA256:
        raise _reject("TDD-Bench id-list hash differs from the pinned object.")
    git_oid = hashlib.sha1(
        f"blob {len(content)}\0".encode("ascii") + content, usedforsecurity=False
    ).hexdigest()
    if git_oid != OFFICIAL_TDD_ID_LIST_BLOB_OID:
        raise _reject("TDD-Bench id-list Git blob differs from the pinned object.")
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise _reject("TDD-Bench id list is not ASCII.") from exc
    if content.endswith((b"\r", b"\n")) or content.count(b"\r\n") != EXPECTED_TDD_MEMBERS - 1:
        raise _reject("TDD-Bench id list does not use exact CRLF delimiters without a terminator.")
    if b"\r" in content.replace(b"\r\n", b"") or content.count(b"\n") != EXPECTED_TDD_MEMBERS - 1:
        raise _reject("TDD-Bench id list contains noncanonical line endings.")
    values = tuple(text.split("\r\n"))
    if len(values) != EXPECTED_TDD_MEMBERS or len(set(values)) != len(values):
        raise _reject("TDD-Bench id list is not the exact unique 449-member sequence.")
    if any(_INSTANCE_ID.fullmatch(value) is None for value in values):
        raise _reject("TDD-Bench id list contains an invalid instance ID.")
    return values


def _verify_parquet_bytes(content: bytes) -> None:
    if (
        len(content) != OFFICIAL_SOURCE_DATASET_BYTES
        or hashlib.sha256(content).hexdigest() != OFFICIAL_SOURCE_DATASET_LFS_SHA256
    ):
        raise _reject("Source dataset bytes differ from the pinned LFS object.")
    pointer = _canonical_lfs_pointer()
    if hashlib.sha256(pointer).hexdigest() != SOURCE_DATASET_LFS_POINTER_SHA256:
        raise _reject("Internal source dataset LFS pointer identity is inconsistent.")
    oid = hashlib.sha1(
        f"blob {len(pointer)}\0".encode("ascii") + pointer, usedforsecurity=False
    ).hexdigest()
    if oid != OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID:
        raise _reject("Source dataset LFS pointer Git blob is inconsistent.")


def _canonical_lfs_pointer() -> bytes:
    return (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{OFFICIAL_SOURCE_DATASET_LFS_SHA256}\n"
        f"size {OFFICIAL_SOURCE_DATASET_BYTES}\n"
    ).encode("ascii")


def _run_worker(
    parser_python: Path,
    worker_source: bytes,
    parquet: bytes,
    *,
    projection_instance_ids: tuple[str, ...] = (),
) -> dict[str, object]:
    _require_dedicated_parser_python(parser_python)
    temporary_base = Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="reproassert-v02-parquet-", dir=temporary_base
    ) as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        worker_path = root / "parser.py"
        parquet_path = root / "0000.parquet"
        request_path = root / "request.json"
        output_path = root / "result.json"
        write_bytes_exclusive(worker_path, worker_source)
        write_bytes_exclusive(parquet_path, parquet)
        command = [str(parser_python), "-I", "-B", str(worker_path), str(parquet_path)]
        if projection_instance_ids:
            request = {
                "instance_ids": list(projection_instance_ids),
                "protocol": PROJECTION_REQUEST_PROTOCOL,
            }
            write_bytes_exclusive(request_path, _canonical(request) + b"\n")
            command.append(str(request_path))
        process: subprocess.Popen[bytes] | None = None
        try:
            with open_exclusive_file(output_path) as output_stream:
                process = subprocess.Popen(
                    command,
                    cwd=root,
                    stdin=subprocess.DEVNULL,
                    stdout=output_stream,
                    stderr=subprocess.DEVNULL,
                    env={
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PYTHONHASHSEED": "0",
                        "PYTHONNOUSERSITE": "1",
                    },
                    close_fds=True,
                    start_new_session=True,
                )
                try:
                    returncode = process.wait(timeout=_WORKER_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired as exc:
                    _kill_process_group(process)
                    raise _reject("Pinned Parquet parser exceeded its time limit.") from exc
                finally:
                    _kill_process_group(process)
        except OSError as exc:
            if process is not None:
                _kill_process_group(process)
            raise _reject("Pinned Parquet parser could not complete safely.") from exc
        output_bytes = _read_bounded_regular(
            output_path, _MAX_WORKER_OUTPUT_BYTES, "pinned Parquet parser output"
        )
    if returncode != 0:
        raise _reject("Pinned Parquet parser rejected the frozen dataset artifact.")
    try:
        decoded = json.loads(output_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _reject("Pinned Parquet parser returned invalid structured output.") from exc
    if output_bytes != _canonical(decoded) + b"\n" or not isinstance(decoded, dict):
        raise _reject("Pinned Parquet parser output is not canonical JSON.")
    if (
        set(decoded) != {"parser_protocol", "result"}
        or decoded.get("parser_protocol") != PARSER_PROTOCOL
    ):
        raise _reject("Pinned Parquet parser protocol is invalid.")
    worker = decoded.get("result")
    if not isinstance(worker, dict):
        raise _reject("Pinned Parquet parser result is invalid.")
    return cast(dict[str, object], worker)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    """Best-effort cleanup for the fixed worker and any process it might have spawned."""

    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _validate_worker_result(worker: dict[str, object]) -> list[dict[str, object]]:
    if set(worker) != _WORKER_RESULT_KEYS:
        raise _reject("Pinned Parquet parser result fields are invalid.")
    exact = {
        "column_count": EXPECTED_SOURCE_COLUMNS,
        "columns": list(_COLUMNS),
        "parquet_created_by": "parquet-cpp-arrow version 15.0.2",
        "pyarrow_version": PYARROW_VERSION,
        "row_count": EXPECTED_SOURCE_ROWS,
        "row_group_count": 1,
        "unique_instance_id_count": EXPECTED_SOURCE_ROWS,
    }
    if any(worker.get(key) != value for key, value in exact.items()):
        raise _reject("Pinned Parquet parser result differs from the frozen split contract.")
    for name in ("all_rows_commitment_sha256", "schema_sha256"):
        if (
            not isinstance(worker.get(name), str)
            or _SHA256.fullmatch(cast(str, worker[name])) is None
        ):
            raise _reject("Pinned Parquet parser result hash is invalid.")
    raw_rows = worker.get("rows")
    if not isinstance(raw_rows, list) or len(raw_rows) != EXPECTED_SOURCE_ROWS:
        raise _reject("Pinned Parquet parser did not return exactly 500 row commitments.")
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for ordinal, item in enumerate(raw_rows):
        if not isinstance(item, dict) or set(item) != _ROW_KEYS:
            raise _reject("Pinned Parquet row commitment fields are invalid.")
        row = cast(dict[str, object], item)
        instance_id = row.get("instance_id")
        if (
            not isinstance(instance_id, str)
            or _INSTANCE_ID.fullmatch(instance_id) is None
            or instance_id in seen
            or row.get("row_ordinal") != ordinal
        ):
            raise _reject("Pinned Parquet row identity or ordinal is invalid.")
        for name in ("identity_sha256", "row_sha256"):
            value = row.get(name)
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise _reject("Pinned Parquet row commitment hash is invalid.")
        seen.add(instance_id)
        rows.append(row)
    if len(seen) != EXPECTED_SOURCE_ROWS:
        raise _reject("Pinned Parquet parser did not prove 500 unique instance IDs.")
    if worker["all_rows_commitment_sha256"] != hashlib.sha256(_canonical(rows)).hexdigest():
        raise _reject("Pinned Parquet all-row commitment is inconsistent.")
    _validate_leak_audit_rows(worker.get("leak_audit_rows"), rows)
    _validate_issue_projections(worker.get("issue_projections"), worker["leak_audit_rows"])
    return rows


def _validate_leak_audit_rows(raw: object, rows: list[dict[str, object]]) -> None:
    if not isinstance(raw, list) or len(raw) != EXPECTED_SOURCE_ROWS:
        raise _reject("Pinned Parquet parser did not return the complete oracle-leak audit.")
    for ordinal, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != _LEAK_AUDIT_KEYS:
            raise _reject("Pinned Parquet oracle-leak audit fields are invalid.")
        expected_instance = rows[ordinal]["instance_id"]
        issue_bytes = item.get("issue_text_bytes")
        booleans = (
            item.get("direct_own_fixing_pr_reference"),
            item.get("production_added_line_overlap"),
            item.get("test_added_line_overlap"),
        )
        if (
            item.get("instance_id") != expected_instance
            or item.get("row_ordinal") != ordinal
            or not isinstance(item.get("base_commit"), str)
            or _GIT_OID.fullmatch(cast(str, item["base_commit"])) is None
            or not isinstance(item.get("repo"), str)
            or _REPOSITORY.fullmatch(cast(str, item["repo"])) is None
            or not isinstance(item.get("difficulty"), str)
            or not 1 <= len(cast(str, item["difficulty"])) <= 100
            or type(issue_bytes) is not int
            or not 0 <= issue_bytes <= 512 * 1024
            or any(type(value) is not bool for value in booleans)
            or item.get("oracle_leak_free") is not (not any(cast(tuple[bool, ...], booleans)))
        ):
            raise _reject("Pinned Parquet oracle-leak audit values are inconsistent.")
        digest = item.get("issue_text_sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise _reject("Pinned Parquet issue-text commitment is invalid.")


def _validate_issue_projections(raw: object, audits: object) -> None:
    if not isinstance(raw, list) or len(raw) > 20 or not isinstance(audits, list):
        raise _reject("Pinned Parquet issue projections are invalid.")
    audit_by_id = {
        item["instance_id"]: item
        for item in audits
        if isinstance(item, dict) and "instance_id" in item
    }
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) != _ISSUE_PROJECTION_KEYS:
            raise _reject("Pinned Parquet issue projection fields are invalid.")
        instance_id = item.get("instance_id")
        text = item.get("problem_statement")
        audit = audit_by_id.get(instance_id) if isinstance(instance_id, str) else None
        if (
            not isinstance(instance_id, str)
            or _INSTANCE_ID.fullmatch(instance_id) is None
            or instance_id in seen
            or not isinstance(text, str)
            or not text
            or len(text.encode("utf-8")) > 512 * 1024
            or not isinstance(audit, dict)
            or audit.get("oracle_leak_free") is not True
            or hashlib.sha256(text.encode("utf-8")).hexdigest() != audit.get("issue_text_sha256")
            or len(text.encode("utf-8")) != audit.get("issue_text_bytes")
        ):
            raise _reject("Pinned Parquet issue projection is unsafe or inconsistent.")
        seen.add(instance_id)


def _require_dedicated_parser_python(path: Path) -> None:
    if not path.is_absolute() or path.parent.name != "bin":
        raise _reject("Pinned Parquet parser Python must be an absolute dedicated-venv path.")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise _reject("Pinned Parquet parser Python is unavailable.") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & stat.S_IXUSR == 0:
        raise _reject("Pinned Parquet parser Python is not an executable regular file.")
    try:
        _read_bounded_regular(path.parent.parent / "pyvenv.cfg", 16 * 1024, "parser pyvenv.cfg")
    except (OSError, PolicyRejection) as exc:
        raise _reject("Pinned Parquet parser Python is not inside a dedicated venv.") from exc
    try:
        if path.parent.parent.resolve(strict=True) == Path(sys.prefix).resolve(strict=True):
            raise _reject("Pinned Parquet parser must use a separately supplied venv.")
    except OSError as exc:
        raise _reject("Pinned Parquet parser venv cannot be resolved safely.") from exc


def _decode_canonical_receipt(content: bytes) -> dict[str, object]:
    try:
        decoded = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _reject("Private dataset parser receipt is invalid JSON.") from exc
    if not isinstance(decoded, dict) or content != _canonical(decoded) + b"\n":
        raise _reject("Private dataset parser receipt is not exact canonical JSON.")
    if set(decoded) != {"algorithm", "dataset", "parser", "upstream"}:
        raise _reject("Private dataset parser receipt fields are invalid.")
    if decoded.get("algorithm") != DATASET_PARSER_RECEIPT_ALGORITHM:
        raise _reject("Private dataset parser receipt algorithm is invalid.")
    return cast(dict[str, object], decoded)


def _validate_private_receipt(content: bytes) -> dict[str, object]:
    """Validate every public-facing receipt field before projecting it."""

    receipt = _decode_canonical_receipt(content)
    dataset = receipt.get("dataset")
    parser = receipt.get("parser")
    upstream = receipt.get("upstream")
    if (
        not isinstance(dataset, dict)
        or not isinstance(parser, dict)
        or not isinstance(upstream, dict)
    ):
        raise _reject("Private dataset parser receipt sections are invalid.")
    expected_dataset_keys = {
        "all_rows_commitment_sha256",
        "column_count",
        "columns",
        "issue_projections",
        "issue_projections_sha256",
        "joined_tdd_row_count",
        "joined_tdd_rows",
        "joined_tdd_rows_sha256",
        "leak_audit_rows",
        "leak_audit_rows_sha256",
        "parquet_created_by",
        "row_count",
        "row_group_count",
        "schema_sha256",
        "source_dataset_transform",
        "unique_instance_id_count",
    }
    exact_dataset = {
        "column_count": EXPECTED_SOURCE_COLUMNS,
        "columns": list(_COLUMNS),
        "joined_tdd_row_count": EXPECTED_TDD_MEMBERS,
        "parquet_created_by": "parquet-cpp-arrow version 15.0.2",
        "row_count": EXPECTED_SOURCE_ROWS,
        "row_group_count": 1,
        "source_dataset_transform": SOURCE_DATASET_TRANSFORM,
        "unique_instance_id_count": EXPECTED_SOURCE_ROWS,
    }
    if set(dataset) != expected_dataset_keys or any(
        dataset.get(name) != value for name, value in exact_dataset.items()
    ):
        raise _reject("Private dataset parser receipt shape evidence is invalid.")
    for name in (
        "all_rows_commitment_sha256",
        "issue_projections_sha256",
        "joined_tdd_rows_sha256",
        "leak_audit_rows_sha256",
        "schema_sha256",
    ):
        if (
            not isinstance(dataset.get(name), str)
            or _SHA256.fullmatch(cast(str, dataset[name])) is None
        ):
            raise _reject("Private dataset parser receipt commitment is invalid.")
    joined = dataset.get("joined_tdd_rows")
    if not isinstance(joined, list) or len(joined) != EXPECTED_TDD_MEMBERS:
        raise _reject("Private dataset parser receipt join evidence is invalid.")
    instance_ids: set[str] = set()
    source_ordinals: set[int] = set()
    for membership_ordinal, item in enumerate(joined, start=1):
        if not isinstance(item, dict) or set(item) != _JOINED_ROW_KEYS:
            raise _reject("Private dataset parser receipt joined-row fields are invalid.")
        instance_id = item.get("instance_id")
        source_ordinal = item.get("source_dataset_row_ordinal")
        if (
            not isinstance(instance_id, str)
            or _INSTANCE_ID.fullmatch(instance_id) is None
            or instance_id in instance_ids
            or type(source_ordinal) is not int
            or not 0 <= source_ordinal < EXPECTED_SOURCE_ROWS
            or source_ordinal in source_ordinals
            or item.get("tdd_membership_ordinal") != membership_ordinal
        ):
            raise _reject("Private dataset parser receipt joined-row identity is invalid.")
        for name in ("identity_sha256", "source_dataset_row_sha256"):
            value = item.get(name)
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise _reject("Private dataset parser receipt joined-row commitment is invalid.")
        instance_ids.add(instance_id)
        source_ordinals.add(source_ordinal)
    if dataset["joined_tdd_rows_sha256"] != hashlib.sha256(_canonical(joined)).hexdigest():
        raise _reject("Private dataset parser receipt join commitment is inconsistent.")
    leak_audits = _validate_receipt_leak_audits(dataset.get("leak_audit_rows"))
    if dataset["leak_audit_rows_sha256"] != hashlib.sha256(_canonical(leak_audits)).hexdigest():
        raise _reject("Private dataset parser receipt oracle-leak commitment is inconsistent.")
    projections = dataset.get("issue_projections")
    _validate_issue_projections(projections, leak_audits)
    if dataset["issue_projections_sha256"] != hashlib.sha256(_canonical(projections)).hexdigest():
        raise _reject("Private dataset parser receipt issue-projection commitment is inconsistent.")
    expected_parser = {
        "parser_protocol": PARSER_PROTOCOL,
        "pyarrow_version": PYARROW_VERSION,
    }
    if set(parser) != {*expected_parser, "trusted_worker_sha256"} or any(
        parser.get(name) != value for name, value in expected_parser.items()
    ):
        raise _reject("Private dataset parser receipt parser identity is invalid.")
    worker_sha = parser.get("trusted_worker_sha256")
    if not isinstance(worker_sha, str) or _SHA256.fullmatch(worker_sha) is None:
        raise _reject("Private dataset parser receipt worker identity is invalid.")
    shipped_worker = _read_bounded_regular(
        Path(__file__).with_name("_benchmark_v02_parquet_worker.py"),
        _MAX_WORKER_BYTES,
        "trusted Parquet worker",
    )
    if worker_sha != hashlib.sha256(shipped_worker).hexdigest():
        raise _reject("Private dataset parser receipt worker differs from the shipped worker.")
    _validate_upstream_record(upstream)
    return receipt


def _validate_receipt_leak_audits(raw: object) -> list[dict[str, object]]:
    if not isinstance(raw, list) or len(raw) != EXPECTED_SOURCE_ROWS:
        raise _reject("Private dataset parser receipt oracle-leak audit is incomplete.")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for ordinal, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != _LEAK_AUDIT_KEYS:
            raise _reject("Private dataset parser receipt oracle-leak fields are invalid.")
        instance_id = item.get("instance_id")
        issue_bytes = item.get("issue_text_bytes")
        flags = (
            item.get("direct_own_fixing_pr_reference"),
            item.get("production_added_line_overlap"),
            item.get("test_added_line_overlap"),
        )
        digest = item.get("issue_text_sha256")
        if (
            not isinstance(instance_id, str)
            or _INSTANCE_ID.fullmatch(instance_id) is None
            or instance_id in seen
            or item.get("row_ordinal") != ordinal
            or not isinstance(item.get("base_commit"), str)
            or _GIT_OID.fullmatch(cast(str, item["base_commit"])) is None
            or not isinstance(item.get("repo"), str)
            or _REPOSITORY.fullmatch(cast(str, item["repo"])) is None
            or not isinstance(item.get("difficulty"), str)
            or not 1 <= len(cast(str, item["difficulty"])) <= 100
            or type(issue_bytes) is not int
            or not 0 <= issue_bytes <= 512 * 1024
            or any(type(value) is not bool for value in flags)
            or item.get("oracle_leak_free") is not (not any(cast(tuple[bool, ...], flags)))
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
        ):
            raise _reject("Private dataset parser receipt oracle-leak values are invalid.")
        seen.add(instance_id)
        result.append(cast(dict[str, object], item))
    return result


def _validate_upstream_record(upstream: dict[object, object]) -> None:
    if set(upstream) != {"source_dataset", "tdd_bench", "verification"}:
        raise _reject("Private dataset parser receipt upstream evidence is invalid.")
    source = upstream.get("source_dataset")
    tdd = upstream.get("tdd_bench")
    verification = upstream.get("verification")
    pointer = _canonical_lfs_pointer()
    expected_source = {
        "artifact_bytes": OFFICIAL_SOURCE_DATASET_BYTES,
        "artifact_git_blob_oid": OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID,
        "artifact_lfs_sha256": OFFICIAL_SOURCE_DATASET_LFS_SHA256,
        "artifact_path": OFFICIAL_SOURCE_DATASET_PATH,
        "artifact_sha256": OFFICIAL_SOURCE_DATASET_LFS_SHA256,
        "artifact_xet_sha256": OFFICIAL_SOURCE_DATASET_XET_SHA256,
        "git_sha": OFFICIAL_SOURCE_DATASET_GIT_SHA,
        "lfs_pointer_bytes": len(pointer),
        "lfs_pointer_sha256": SOURCE_DATASET_LFS_POINTER_SHA256,
        "repository_url": SOURCE_DATASET_REPOSITORY_URL,
        "root_tree_oid": OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID,
        "split": SOURCE_DATASET_SPLIT,
    }
    expected_tdd = {
        "git_sha": OFFICIAL_TDD_BENCH_GIT_SHA,
        "id_list_blob_oid": OFFICIAL_TDD_ID_LIST_BLOB_OID,
        "id_list_bytes": OFFICIAL_TDD_ID_LIST_BYTES,
        "id_list_path": OFFICIAL_TDD_ID_LIST_PATH,
        "id_list_sha256": OFFICIAL_TDD_ID_LIST_SHA256,
        "member_count": EXPECTED_TDD_MEMBERS,
        "repository_url": TDD_BENCH_REPOSITORY_URL,
        "root_tree_oid": OFFICIAL_TDD_BENCH_ROOT_TREE_OID,
    }
    expected_verification_keys = {
        "git_graph_verified",
        "lfs_artifact_verified",
        "object_witness_sha256",
        "upstream_evidence_sha256",
        "xet_resolution_cross_bound",
        "xet_resolution_transferable_cryptographic_proof",
        "xet_resolution_transport",
    }
    if (
        source != expected_source
        or tdd != expected_tdd
        or not isinstance(verification, dict)
        or set(verification) != expected_verification_keys
        or verification.get("git_graph_verified") is not True
        or verification.get("lfs_artifact_verified") is not True
        or verification.get("xet_resolution_cross_bound") is not True
        or verification.get("xet_resolution_transport") != "https_tls_at_collection"
        or verification.get("xet_resolution_transferable_cryptographic_proof") is not False
        or any(
            not isinstance(verification.get(name), str)
            or _SHA256.fullmatch(cast(str, verification[name])) is None
            for name in ("object_witness_sha256", "upstream_evidence_sha256")
        )
    ):
        raise _reject("Private dataset parser receipt is not bound to the frozen upstream objects.")


def _cross_bind_upstream(
    receipt: dict[str, object], verified: VerifiedV02UpstreamProvenance
) -> None:
    require_v02_upstream_provenance(verified)
    upstream = cast(dict[str, object], receipt["upstream"])
    source = cast(dict[str, object], upstream["source_dataset"])
    tdd = cast(dict[str, object], upstream["tdd_bench"])
    verification = cast(dict[str, object], upstream["verification"])
    observed = (
        tdd["git_sha"],
        tdd["root_tree_oid"],
        tdd["id_list_blob_oid"],
        tdd["id_list_sha256"],
        source["git_sha"],
        source["root_tree_oid"],
        source["artifact_git_blob_oid"],
        source["artifact_lfs_sha256"],
        source["artifact_bytes"],
        source["artifact_xet_sha256"],
        verification["object_witness_sha256"],
        verification["upstream_evidence_sha256"],
    )
    expected = (
        verified.tdd_bench_git_sha,
        verified.tdd_bench_root_tree_oid,
        verified.tdd_id_list_blob_oid,
        verified.tdd_id_list_sha256,
        verified.source_dataset_git_sha,
        verified.source_dataset_root_tree_oid,
        verified.source_dataset_artifact_git_blob_oid,
        verified.source_dataset_artifact_lfs_sha256,
        verified.source_dataset_artifact_lfs_bytes,
        verified.source_dataset_artifact_xet_sha256,
        verified.witness_sha256,
        verified.evidence_sha256,
    )
    if observed != expected:
        raise _reject("Dataset parser receipt differs from the freshly verified upstream graph.")


def load_prepared_v02_dataset_receipt(path: Path) -> dict[str, object]:
    """Load a validated preparation-only receipt for cohort planning; never a live capability."""

    content = _read_bounded_regular(Path(path), _MAX_RECEIPT_BYTES, "dataset parser receipt")
    return _validate_private_receipt(content)


def _read_bounded_regular(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            content = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label} could not be read safely.") from exc
    if len(content) > limit:
        raise _reject(f"{label} exceeds its byte limit.")
    return content


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _reject("Dataset evidence cannot be represented as canonical JSON.") from exc


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_dataset", message)
