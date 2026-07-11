"""Container-only worker for extracting evaluator-private SWE-bench gold artifacts.

The worker never writes hidden bytes to stdout or stderr. Its only output is a bounded tmpfs
directory supplied by the trusted controller.
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
PROTOCOL = "reproassert-v02-hidden-extraction-worker-v1"
REQUEST_PROTOCOL = "reproassert-v02-hidden-extraction-request-v1"
PARQUET_SHA256 = "a45b1fe4e2f0c8390b2b2938ac83e92ed5979000856808f3679c07812e9e6dcd"
PARQUET_BYTES = 2_096_679
ROW_COUNT = 500
_INSTANCE_ID = re.compile(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[1-9][0-9]*\Z")
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_REQUEST_BYTES = 32 * 1024
_MAX_PATCH_BYTES = 1024 * 1024
_MAX_METADATA_BYTES = 8 * 1024


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _read_regular(path: Path, exact_bytes: int | None, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("input identity mismatch")
        content = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    if len(content) > maximum or (exact_bytes is not None and len(content) != exact_bytes):
        raise ValueError("input size mismatch")
    return content


def _load_request(path: Path) -> list[dict[str, str]]:
    content = _read_regular(path, None, _MAX_REQUEST_BYTES)
    decoded = json.loads(content)
    if (
        not isinstance(decoded, dict)
        or content != _canonical(decoded) + b"\n"
        or set(decoded) != {"cases", "protocol"}
        or decoded.get("protocol") != REQUEST_PROTOCOL
    ):
        raise ValueError("request envelope mismatch")
    raw_cases = decoded.get("cases")
    if not isinstance(raw_cases, list) or len(raw_cases) != 20:
        raise ValueError("request case count mismatch")
    cases: list[dict[str, str]] = []
    for ordinal, item in enumerate(raw_cases, 1):
        if not isinstance(item, dict) or set(item) != {"case_id", "instance_id"}:
            raise ValueError("request case mismatch")
        case_id = item.get("case_id")
        instance_id = item.get("instance_id")
        if (
            case_id != f"rk-v0.2-{ordinal:03d}"
            or not isinstance(instance_id, str)
            or _INSTANCE_ID.fullmatch(instance_id) is None
        ):
            raise ValueError("request identity mismatch")
        cases.append({"case_id": cast(str, case_id), "instance_id": instance_id})
    if len({item["instance_id"] for item in cases}) != 20:
        raise ValueError("request instances repeat")
    return cases


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short output write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _text(value: Any, label: str, *, allow_empty: bool, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} type mismatch")
    content = value.encode("utf-8")
    if (not allow_empty and not content) or len(content) > maximum:
        raise ValueError(f"{label} size mismatch")
    return content


def _derive(dataset_path: Path, request_path: Path, output_root: Path) -> None:
    if os.environ.get("REPROASSERT_HIDDEN_CONTAINER") != "attested-v1":
        raise ValueError("container boundary missing")
    parquet_bytes = _read_regular(dataset_path, PARQUET_BYTES, PARQUET_BYTES)
    if hashlib.sha256(parquet_bytes).hexdigest() != PARQUET_SHA256:
        raise ValueError("dataset digest mismatch")
    cases = _load_request(request_path)
    pa = importlib.import_module("pyarrow")
    pq = importlib.import_module("pyarrow.parquet")
    if getattr(pa, "__version__", None) != PYARROW_VERSION:
        raise ValueError("pyarrow identity mismatch")
    table = pq.read_table(pa.BufferReader(parquet_bytes), use_threads=False)
    if table.num_rows != ROW_COUNT:
        raise ValueError("dataset row count mismatch")
    rows = cast(list[dict[str, Any]], table.to_pylist())
    by_id = {cast(str, row.get("instance_id")): (ordinal, row) for ordinal, row in enumerate(rows)}
    artifacts: list[dict[str, object]] = []
    for requested in cases:
        selected = by_id.get(requested["instance_id"])
        if selected is None:
            raise ValueError("requested row missing")
        row_ordinal, row = selected
        case_id = requested["case_id"]
        production = _text(
            row.get("patch"), "production patch", allow_empty=False, maximum=_MAX_PATCH_BYTES
        )
        developer = _text(
            row.get("test_patch"), "developer patch", allow_empty=False, maximum=_MAX_PATCH_BYTES
        )
        repo = row.get("repo")
        base_commit = row.get("base_commit")
        environment = row.get("environment_setup_commit")
        if (
            not isinstance(repo, str)
            or not isinstance(base_commit, str)
            or _GIT_SHA.fullmatch(base_commit) is None
            or not isinstance(environment, str)
            or _GIT_SHA.fullmatch(environment) is None
        ):
            raise ValueError("row metadata mismatch")
        case_root = output_root / case_id
        case_root.mkdir(mode=0o700)
        _write_exclusive(case_root / "production.patch", production)
        _write_exclusive(case_root / "developer-tests.patch", developer)
        created_at, difficulty, version = (
            row.get("created_at"),
            row.get("difficulty"),
            row.get("version"),
        )
        if not all(isinstance(value, str) for value in (created_at, difficulty, version)):
            raise ValueError("row metadata type mismatch")
        metadata = {
            "base_commit": base_commit,
            "case_id": case_id,
            "created_at": created_at,
            "difficulty": difficulty,
            "environment_setup_commit": environment,
            "instance_id": requested["instance_id"],
            "repo": repo,
            "source_dataset_row_ordinal": row_ordinal,
            "source_row_sha256": hashlib.sha256(_canonical(row)).hexdigest(),
            "version": version,
        }
        encoded_metadata = _canonical(metadata) + b"\n"
        if len(encoded_metadata) > _MAX_METADATA_BYTES:
            raise ValueError("metadata exceeds bound")
        _write_exclusive(case_root / "metadata.json", encoded_metadata)
        artifacts.append(
            {
                "case_id": case_id,
                "developer_tests_bytes": len(developer),
                "developer_tests_sha256": hashlib.sha256(developer).hexdigest(),
                "metadata_bytes": len(encoded_metadata),
                "metadata_sha256": hashlib.sha256(encoded_metadata).hexdigest(),
                "production_patch_bytes": len(production),
                "production_patch_sha256": hashlib.sha256(production).hexdigest(),
            }
        )
    manifest = {
        "artifacts": artifacts,
        "case_count": 20,
        "protocol": PROTOCOL,
        "request_sha256": hashlib.sha256(
            _read_regular(request_path, None, _MAX_REQUEST_BYTES)
        ).hexdigest(),
    }
    _write_exclusive(output_root / "manifest.json", _canonical(manifest) + b"\n")


def _limits() -> None:
    for kind, requested in (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_CPU, 60),
        (resource.RLIMIT_FSIZE, _MAX_PATCH_BYTES),
        (resource.RLIMIT_NOFILE, 64),
    ):
        _soft, hard = resource.getrlimit(kind)
        value = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
        resource.setrlimit(kind, (value, value))


def main() -> int:
    if len(sys.argv) != 4:
        return 2
    try:
        _limits()
        _derive(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    except Exception:
        # Hidden values and exception messages are intentionally never rendered.
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
