"""Hash-locked PyArrow worker for evaluator-private v0.2 evidence preparation.

This file is copied into a private temporary directory and executed by a separately supplied
virtual environment. It deliberately has no dependency on the installed ReproAssert package.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import resource
import stat
import sys
from pathlib import Path
from typing import Any, cast

PYARROW_VERSION = "24.0.0"
PARSER_PROTOCOL = "reproassert-v02-pyarrow-worker-v1"
PROJECTION_REQUEST_PROTOCOL = "reproassert-v02-dataset-projection-request-v1"
PARQUET_SHA256 = "a45b1fe4e2f0c8390b2b2938ac83e92ed5979000856808f3679c07812e9e6dcd"
PARQUET_BYTES = 2_096_679
PARQUET_CREATED_BY = "parquet-cpp-arrow version 15.0.2"
ROW_COUNT = 500
ROW_GROUP_COUNT = 1
COLUMNS = (
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
DROP_COLUMNS = frozenset({"PASS_TO_PASS", "FAIL_TO_PASS"})
_INSTANCE_ID = re.compile(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[1-9][0-9]*\Z")
_MAX_REQUEST_BYTES = 16 * 1024
_MAX_PROJECTION_CASES = 20


def _set_resource_limits() -> None:
    limits = [
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_CPU, 30),
        (resource.RLIMIT_FSIZE, 4 * 1024 * 1024),
        (resource.RLIMIT_NOFILE, 64),
    ]
    # macOS rejects useful AS, DATA, and RSS limits for this PyArrow process with EINVAL. CPU,
    # output-file, descriptor, wall-clock, and parent-read limits remain enforced, but memory must
    # be bounded by a production container/microVM. This worker is evidence-preparation only.
    if sys.platform != "darwin" and hasattr(resource, "RLIMIT_AS"):
        limits.append((resource.RLIMIT_AS, 2 * 1024 * 1024 * 1024))
    for kind, requested in limits:
        _current_soft, current_hard = resource.getrlimit(kind)
        hard = requested if current_hard == resource.RLIM_INFINITY else min(requested, current_hard)
        resource.setrlimit(kind, (min(requested, hard), hard))


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _read_exact(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != PARQUET_BYTES:
            raise ValueError("dataset artifact identity mismatch")
        content = b""
        while len(content) <= PARQUET_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, PARQUET_BYTES + 1 - len(content)))
            if not chunk:
                break
            content += chunk
    finally:
        os.close(descriptor)
    if len(content) != PARQUET_BYTES or hashlib.sha256(content).hexdigest() != PARQUET_SHA256:
        raise ValueError("dataset artifact identity mismatch")
    return content


def _derive(path: Path, projection_instance_ids: tuple[str, ...] = ()) -> dict[str, object]:
    in_attested_container = os.environ.get("REPROASSERT_DATASET_CONTAINER") == "attested-v1"
    if sys.prefix == sys.base_prefix and not in_attested_container:
        raise ValueError("parser must run in a dedicated virtual environment")
    pa = importlib.import_module("pyarrow")
    pq = importlib.import_module("pyarrow.parquet")
    if getattr(pa, "__version__", None) != PYARROW_VERSION:
        raise ValueError("untrusted pyarrow version")
    package_file = getattr(pa, "__file__", None)
    if not isinstance(package_file, str) or not Path(package_file).resolve().is_relative_to(
        Path(sys.prefix).resolve()
    ):
        raise ValueError("pyarrow is not installed inside the dedicated environment")

    content = _read_exact(path)
    parquet = pq.ParquetFile(pa.BufferReader(content))
    metadata = parquet.metadata
    if (
        metadata.num_rows != ROW_COUNT
        or metadata.num_row_groups != ROW_GROUP_COUNT
        or metadata.num_columns != len(COLUMNS)
        or metadata.created_by != PARQUET_CREATED_BY
    ):
        raise ValueError("parquet metadata differs from the frozen split")
    schema = parquet.schema_arrow
    if tuple(schema.names) != COLUMNS:
        raise ValueError("parquet columns differ from the frozen split")
    schema_record: list[dict[str, object]] = []
    for field in schema:
        if str(field.type) != "string" or not field.nullable:
            raise ValueError("parquet field types differ from the frozen split")
        schema_record.append(
            {"name": field.name, "nullable": field.nullable, "type": str(field.type)}
        )

    table = parquet.read(use_threads=False)
    if table.num_rows != ROW_COUNT or table.num_columns != len(COLUMNS):
        raise ValueError("parsed table shape differs from the frozen split")
    rows = cast(list[dict[str, Any]], table.to_pylist())
    commitments: list[dict[str, object]] = []
    leak_audit_rows: list[dict[str, object]] = []
    projection_by_id: dict[str, dict[str, str]] = {}
    requested = set(projection_instance_ids)
    seen: set[str] = set()
    for ordinal, row in enumerate(rows):
        if tuple(row) != COLUMNS or any(type(row[name]) is not str for name in COLUMNS):
            raise ValueError("parsed row types differ from the frozen split")
        instance_id = cast(str, row["instance_id"])
        if _INSTANCE_ID.fullmatch(instance_id) is None or instance_id in seen:
            raise ValueError("dataset instance IDs are invalid or duplicated")
        seen.add(instance_id)
        transformed = {name: row[name] for name in COLUMNS if name not in DROP_COLUMNS}
        if set(row) - set(transformed) != DROP_COLUMNS or len(transformed) != 11:
            raise ValueError("dataset transform removed unexpected fields")
        row_bytes = _canonical(transformed) + b"\n"
        identity = {
            "base_commit": row["base_commit"],
            "instance_id": instance_id,
            "repo": row["repo"],
        }
        commitments.append(
            {
                "identity_sha256": hashlib.sha256(_canonical(identity)).hexdigest(),
                "instance_id": instance_id,
                "row_ordinal": ordinal,
                "row_sha256": hashlib.sha256(row_bytes).hexdigest(),
            }
        )
        audit = _audit_row(row)
        leak_audit_rows.append(
            {
                "base_commit": row["base_commit"],
                "direct_own_fixing_pr_reference": audit[0],
                "difficulty": row["difficulty"],
                "instance_id": instance_id,
                "issue_text_bytes": len(cast(str, row["problem_statement"]).encode("utf-8")),
                "issue_text_sha256": hashlib.sha256(
                    cast(str, row["problem_statement"]).encode("utf-8")
                ).hexdigest(),
                "oracle_leak_free": not any(audit),
                "production_added_line_overlap": audit[1],
                "repo": row["repo"],
                "row_ordinal": ordinal,
                "test_added_line_overlap": audit[2],
            }
        )
        if instance_id in requested:
            if any(audit):
                raise ValueError(
                    "requested issue projection is quarantined by the oracle leak audit"
                )
            projection_by_id[instance_id] = {
                "instance_id": instance_id,
                "problem_statement": cast(str, row["problem_statement"]),
            }
    if len(seen) != ROW_COUNT:
        raise ValueError("dataset does not contain 500 unique instance IDs")
    if set(projection_by_id) != requested:
        raise ValueError("requested issue projection is absent from the frozen dataset")
    issue_projections = [projection_by_id[instance_id] for instance_id in projection_instance_ids]
    return {
        "all_rows_commitment_sha256": hashlib.sha256(_canonical(commitments)).hexdigest(),
        "column_count": len(COLUMNS),
        "columns": list(COLUMNS),
        "parquet_created_by": PARQUET_CREATED_BY,
        "pyarrow_version": PYARROW_VERSION,
        "issue_projections": issue_projections,
        "leak_audit_rows": leak_audit_rows,
        "row_count": ROW_COUNT,
        "row_group_count": ROW_GROUP_COUNT,
        "rows": commitments,
        "schema_sha256": hashlib.sha256(_canonical(schema_record)).hexdigest(),
        "unique_instance_id_count": len(seen),
    }


def _audit_row(row: dict[str, Any]) -> tuple[bool, bool, bool]:
    instance_id = cast(str, row["instance_id"])
    fixing_pr_number = instance_id.rsplit("-", 1)[1]
    repo = cast(str, row["repo"])
    issue = cast(str, row["problem_statement"])
    own_url = re.compile(
        rf"https?://github\.com/{re.escape(repo)}/pull/{fixing_pr_number}(?![0-9])",
        re.IGNORECASE,
    )
    shorthand = re.compile(
        rf"(?<![A-Za-z0-9])(?:#\s*|GH-){fixing_pr_number}(?![0-9])",
        re.IGNORECASE,
    )
    direct = own_url.search(issue) is not None or shorthand.search(issue) is not None
    production_overlap = _has_added_line_overlap(issue, cast(str, row["patch"]))
    test_overlap = _has_added_line_overlap(issue, cast(str, row["test_patch"]))
    return direct, production_overlap, test_overlap


def _has_added_line_overlap(issue_text: str, patch: str) -> bool:
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            # Diff indentation and Markdown code-block indentation are presentation details.  The
            # logical added line must match exactly after removing only surrounding whitespace.
            added = line[1:].strip()
            if len(added) >= 40 and added in issue_text:
                return True
    return False


def _read_projection_request(path: Path) -> tuple[str, ...]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= _MAX_REQUEST_BYTES:
            raise ValueError("projection request identity mismatch")
        content = os.read(descriptor, _MAX_REQUEST_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        decoded = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("projection request is invalid JSON") from exc
    if (
        not isinstance(decoded, dict)
        or content != _canonical(decoded) + b"\n"
        or set(decoded) != {"instance_ids", "protocol"}
        or decoded.get("protocol") != PROJECTION_REQUEST_PROTOCOL
    ):
        raise ValueError("projection request is not canonical")
    raw_ids = decoded.get("instance_ids")
    if (
        not isinstance(raw_ids, list)
        or not 1 <= len(raw_ids) <= _MAX_PROJECTION_CASES
        or len(set(cast(list[object], raw_ids))) != len(raw_ids)
        or any(
            not isinstance(value, str) or _INSTANCE_ID.fullmatch(value) is None for value in raw_ids
        )
    ):
        raise ValueError("projection request instance IDs are invalid")
    return tuple(cast(list[str], raw_ids))


def main() -> int:
    if len(sys.argv) not in {2, 3}:
        return 2
    try:
        _set_resource_limits()
        requested = _read_projection_request(Path(sys.argv[2])) if len(sys.argv) == 3 else ()
        result = {
            "parser_protocol": PARSER_PROTOCOL,
            "result": _derive(Path(sys.argv[1]), requested),
        }
        sys.stdout.buffer.write(_canonical(result) + b"\n")
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
