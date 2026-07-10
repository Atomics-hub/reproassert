from __future__ import annotations

import hashlib
import importlib
import io
import json
import os
import resource
import sys
import venv
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import reproassert._benchmark_v02_parquet_worker as parquet_worker
import reproassert.benchmark_v02_dataset as dataset
import reproassert.semantic_issuer as issuer
from reproassert.benchmark_v02_package import V02CaseIdentity
from reproassert.errors import PolicyRejection

CASE = V02CaseIdentity(
    id="rk-v0.2-007",
    repo="owner/repo",
    issue_url="https://github.com/owner/repo/issues/7",
    base_sha="a" * 40,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _blob_oid(content: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(content)}\0".encode() + content, usedforsecurity=False
    ).hexdigest()


def _identity_sha(instance_id: str, *, repo: str = "owner/repo", base: str = "a" * 40) -> str:
    return hashlib.sha256(
        _canonical({"base_commit": base, "instance_id": instance_id, "repo": repo})
    ).hexdigest()


def _worker_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for ordinal in range(dataset.EXPECTED_SOURCE_ROWS):
        instance_id = f"owner__repo-{ordinal + 1}"
        rows.append(
            {
                "identity_sha256": _identity_sha(instance_id),
                "instance_id": instance_id,
                "row_ordinal": ordinal,
                "row_sha256": hashlib.sha256(f"row-{ordinal}".encode()).hexdigest(),
            }
        )
    return rows


def _worker_result(rows: list[dict[str, object]] | None = None) -> dict[str, object]:
    rows = _worker_rows() if rows is None else rows
    audits = [
        {
            "base_commit": "a" * 40,
            "direct_own_fixing_pr_reference": False,
            "difficulty": "<15 min fix",
            "instance_id": row["instance_id"],
            "issue_text_bytes": 1,
            "issue_text_sha256": hashlib.sha256(b"x").hexdigest(),
            "oracle_leak_free": True,
            "production_added_line_overlap": False,
            "repo": "owner/repo",
            "row_ordinal": row["row_ordinal"],
            "test_added_line_overlap": False,
        }
        for row in rows
    ]
    return {
        "all_rows_commitment_sha256": hashlib.sha256(_canonical(rows)).hexdigest(),
        "column_count": dataset.EXPECTED_SOURCE_COLUMNS,
        "columns": list(dataset._COLUMNS),
        "issue_projections": [],
        "leak_audit_rows": audits,
        "parquet_created_by": "parquet-cpp-arrow version 15.0.2",
        "pyarrow_version": dataset.PYARROW_VERSION,
        "row_count": dataset.EXPECTED_SOURCE_ROWS,
        "row_group_count": 1,
        "rows": rows,
        "schema_sha256": "1" * 64,
        "unique_instance_id_count": dataset.EXPECTED_SOURCE_ROWS,
    }


def _patch_synthetic_upstream(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[Path, Path, Path, bytes]:
    members = tuple(f"owner__repo-{ordinal + 1}" for ordinal in range(dataset.EXPECTED_TDD_MEMBERS))
    id_list = "\r\n".join(members).encode()
    parquet = b"PAR1synthetic-frozen-sourcePAR1"
    monkeypatch.setattr(dataset, "OFFICIAL_TDD_ID_LIST_BYTES", len(id_list))
    monkeypatch.setattr(dataset, "OFFICIAL_TDD_ID_LIST_SHA256", hashlib.sha256(id_list).hexdigest())
    monkeypatch.setattr(dataset, "OFFICIAL_TDD_ID_LIST_BLOB_OID", _blob_oid(id_list))
    monkeypatch.setattr(issuer, "OFFICIAL_TDD_ID_LIST_SHA256", hashlib.sha256(id_list).hexdigest())
    monkeypatch.setattr(issuer, "OFFICIAL_TDD_ID_LIST_BLOB_OID", _blob_oid(id_list))
    monkeypatch.setattr(dataset, "OFFICIAL_SOURCE_DATASET_BYTES", len(parquet))
    monkeypatch.setattr(
        dataset, "OFFICIAL_SOURCE_DATASET_LFS_SHA256", hashlib.sha256(parquet).hexdigest()
    )
    monkeypatch.setattr(issuer, "OFFICIAL_SOURCE_DATASET_BYTES", len(parquet))
    monkeypatch.setattr(
        issuer, "OFFICIAL_SOURCE_DATASET_LFS_SHA256", hashlib.sha256(parquet).hexdigest()
    )
    pointer = dataset._canonical_lfs_pointer()
    monkeypatch.setattr(
        dataset,
        "SOURCE_DATASET_LFS_POINTER_SHA256",
        hashlib.sha256(pointer).hexdigest(),
    )
    monkeypatch.setattr(dataset, "OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID", _blob_oid(pointer))
    monkeypatch.setattr(issuer, "OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID", _blob_oid(pointer))
    id_path = tmp_path / "id_list.txt"
    parquet_path = tmp_path / "0000.parquet"
    id_path.write_bytes(id_list)
    parquet_path.write_bytes(parquet)
    witness_path = tmp_path / "upstream-witness.json"
    witness_path.write_text("fixture\n")
    verified = SimpleNamespace(
        evidence_sha256="e" * 64,
        git_graph_verified=True,
        lfs_artifact_verified=True,
        source_dataset_artifact_git_blob_oid=dataset.OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID,
        source_dataset_artifact_lfs_bytes=len(parquet),
        source_dataset_artifact_lfs_sha256=hashlib.sha256(parquet).hexdigest(),
        source_dataset_artifact_xet_sha256=dataset.OFFICIAL_SOURCE_DATASET_XET_SHA256,
        source_dataset_git_sha=dataset.OFFICIAL_SOURCE_DATASET_GIT_SHA,
        source_dataset_root_tree_oid=dataset.OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID,
        tdd_bench_git_sha=dataset.OFFICIAL_TDD_BENCH_GIT_SHA,
        tdd_bench_root_tree_oid=dataset.OFFICIAL_TDD_BENCH_ROOT_TREE_OID,
        tdd_id_list_blob_oid=dataset.OFFICIAL_TDD_ID_LIST_BLOB_OID,
        tdd_id_list_sha256=hashlib.sha256(id_list).hexdigest(),
        witness_sha256="f" * 64,
        xet_resolution_cross_bound=True,
        xet_resolution_transferable_cryptographic_proof=False,
        xet_resolution_transport="https_tls_at_collection",
    )
    monkeypatch.setattr(dataset, "verify_v02_upstream_provenance", lambda *_args, **_kw: verified)
    monkeypatch.setattr(dataset, "require_v02_upstream_provenance", lambda value: value)
    return id_path, parquet_path, witness_path, id_list


def _synthetic_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[bytes, Path, Path, Path]:
    id_path, parquet_path, witness_path, _ = _patch_synthetic_upstream(monkeypatch, tmp_path)
    monkeypatch.setattr(dataset, "_run_worker", lambda *_args, **_kwargs: _worker_result())
    receipt = dataset.render_private_v02_dataset_parser_receipt(
        tdd_id_list_path=id_path,
        source_dataset_path=parquet_path,
        upstream_object_witness_path=witness_path,
        parser_python=tmp_path / "unused" / "bin" / "python",
    )
    return receipt, id_path, parquet_path, witness_path


def _dedicated_python(tmp_path: Path) -> Path:
    root = tmp_path / "parser-venv"
    venv.EnvBuilder(with_pip=False, clear=True).create(root)
    return root / "bin" / "python" if os.name != "nt" else root / "Scripts/python.exe"


def test_synthetic_receipt_is_preparation_only_and_public_projection_is_safe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    receipt, id_path, parquet_path, witness_path = _synthetic_receipt(monkeypatch, tmp_path)
    receipt_path = tmp_path / "private-receipt.json"
    receipt_path.write_bytes(receipt)

    evidence = dataset.prepare_v02_dataset_evidence(
        receipt_path,
        case=CASE,
        instance_id="owner__repo-1",
        tdd_id_list_path=id_path,
        source_dataset_path=parquet_path,
        upstream_object_witness_path=witness_path,
        parser_python=tmp_path / "unused" / "bin" / "python",
    )
    assert evidence.production_eligible is False
    assert evidence.tdd_membership_ordinal == 1
    assert evidence.source_dataset_row_ordinal == 0
    assert evidence.source_dataset_row_sha256 == hashlib.sha256(b"row-0").hexdigest()

    public = json.loads(
        dataset.render_public_v02_dataset_provenance_record(
            receipt_path,
            upstream_object_witness_path=witness_path,
            tdd_id_list_path=id_path,
            source_dataset_path=parquet_path,
        )
    )
    assert public["dataset_checks"] == {
        "column_count": 13,
        "joined_tdd_row_count": 449,
        "row_count": 500,
        "row_group_count": 1,
        "source_dataset_transform": "drop_PASS_TO_PASS_and_FAIL_TO_PASS_v1",
        "unique_instance_id_count": 500,
    }
    serialized = dataset.render_public_v02_dataset_provenance_record(
        receipt_path,
        upstream_object_witness_path=witness_path,
        tdd_id_list_path=id_path,
        source_dataset_path=parquet_path,
    )
    for private_key in (
        b'"all_rows_commitment_sha256"',
        b'"identity_sha256"',
        b'"instance_id"',
        b'"joined_tdd_rows"',
        b'"row_sha256"',
        b'"source_dataset_row_ordinal"',
    ):
        assert private_key not in serialized
    assert public["security"]["host_native_parser_residual_risk"] is True
    assert public["security"]["macos_host_native_memory_limit_enforced"] is False
    assert public["security"]["production_use"] == "evidence_preparation_only"


def test_receipt_binds_exact_upstream_identity_facts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    receipt, _, _, _ = _synthetic_receipt(monkeypatch, tmp_path)
    parsed = json.loads(receipt)
    source = parsed["upstream"]["source_dataset"]
    tdd = parsed["upstream"]["tdd_bench"]
    assert tdd["repository_url"] == dataset.TDD_BENCH_REPOSITORY_URL
    assert tdd["git_sha"] == issuer.OFFICIAL_TDD_BENCH_GIT_SHA
    assert tdd["root_tree_oid"] == issuer.OFFICIAL_TDD_BENCH_ROOT_TREE_OID
    assert tdd["id_list_path"] == "id_list.txt"
    assert tdd["id_list_blob_oid"] == issuer.OFFICIAL_TDD_ID_LIST_BLOB_OID
    assert source["repository_url"] == dataset.SOURCE_DATASET_REPOSITORY_URL
    assert source["git_sha"] == issuer.OFFICIAL_SOURCE_DATASET_GIT_SHA
    assert source["root_tree_oid"] == issuer.OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID
    assert source["artifact_path"] == "default/test/0000.parquet"
    assert source["artifact_git_blob_oid"] == issuer.OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID
    assert source["artifact_lfs_sha256"] == issuer.OFFICIAL_SOURCE_DATASET_LFS_SHA256
    assert source["artifact_bytes"] == issuer.OFFICIAL_SOURCE_DATASET_BYTES
    assert source["artifact_xet_sha256"] == issuer.OFFICIAL_SOURCE_DATASET_XET_SHA256
    assert source["lfs_pointer_bytes"] == len(dataset._canonical_lfs_pointer())


@pytest.mark.parametrize("mutation", ["lf", "terminator", "duplicate", "invalid"])
def test_tdd_membership_bytes_fail_closed(monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    members = [f"owner__repo-{ordinal + 1}" for ordinal in range(dataset.EXPECTED_TDD_MEMBERS)]
    if mutation == "duplicate":
        members[-1] = members[0]
    if mutation == "invalid":
        members[-1] = "not/an-instance"
    separator = "\n" if mutation == "lf" else "\r\n"
    content = separator.join(members).encode() + (b"\r\n" if mutation == "terminator" else b"")
    monkeypatch.setattr(dataset, "OFFICIAL_TDD_ID_LIST_BYTES", len(content))
    monkeypatch.setattr(dataset, "OFFICIAL_TDD_ID_LIST_SHA256", hashlib.sha256(content).hexdigest())
    monkeypatch.setattr(dataset, "OFFICIAL_TDD_ID_LIST_BLOB_OID", _blob_oid(content))
    with pytest.raises(PolicyRejection, match="id list"):
        dataset._verify_tdd_bytes(content)


def test_tdd_bytes_reject_hash_and_git_blob_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    content = b"owner__repo-1"
    monkeypatch.setattr(dataset, "OFFICIAL_TDD_ID_LIST_BYTES", len(content))
    monkeypatch.setattr(dataset, "OFFICIAL_TDD_ID_LIST_SHA256", "0" * 64)
    with pytest.raises(PolicyRejection, match="hash"):
        dataset._verify_tdd_bytes(content)
    monkeypatch.setattr(dataset, "OFFICIAL_TDD_ID_LIST_SHA256", hashlib.sha256(content).hexdigest())
    monkeypatch.setattr(dataset, "OFFICIAL_TDD_ID_LIST_BLOB_OID", "0" * 40)
    with pytest.raises(PolicyRejection, match="Git blob"):
        dataset._verify_tdd_bytes(content)


@pytest.mark.parametrize("mutation", ["duplicate", "ordinal", "hash", "aggregate", "shape"])
def test_worker_result_rejects_false_dataset_proofs(mutation: str) -> None:
    rows = _worker_rows()
    result = _worker_result(rows)
    if mutation == "duplicate":
        rows[-1]["instance_id"] = rows[0]["instance_id"]
    elif mutation == "ordinal":
        rows[-1]["row_ordinal"] = 0
    elif mutation == "hash":
        rows[-1]["row_sha256"] = "invalid"
    elif mutation == "aggregate":
        result["all_rows_commitment_sha256"] = "0" * 64
    else:
        result["row_count"] = 499
    with pytest.raises(PolicyRejection, match="Pinned Parquet"):
        dataset._validate_worker_result(result)


def test_verify_rejects_tampered_receipt_and_wrong_case(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    receipt, id_path, parquet_path, witness_path = _synthetic_receipt(monkeypatch, tmp_path)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(receipt.replace(b'"row_count":500', b'"row_count":499'))
    with pytest.raises(PolicyRejection, match="differs from fresh"):
        dataset.prepare_v02_dataset_evidence(
            receipt_path,
            case=CASE,
            instance_id="owner__repo-1",
            tdd_id_list_path=id_path,
            source_dataset_path=parquet_path,
            upstream_object_witness_path=witness_path,
            parser_python=tmp_path / "unused/bin/python",
        )

    receipt_path.write_bytes(receipt)
    wrong_case = V02CaseIdentity(
        id=CASE.id,
        repo=CASE.repo,
        issue_url=CASE.issue_url,
        base_sha="b" * 40,
    )
    with pytest.raises(PolicyRejection, match="row identity"):
        dataset.prepare_v02_dataset_evidence(
            receipt_path,
            case=wrong_case,
            instance_id="owner__repo-1",
            tdd_id_list_path=id_path,
            source_dataset_path=parquet_path,
            upstream_object_witness_path=witness_path,
            parser_python=tmp_path / "unused/bin/python",
        )


def test_public_projection_rejects_forged_upstream_and_join_commitment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    receipt, id_path, parquet_path, witness_path = _synthetic_receipt(monkeypatch, tmp_path)
    decoded = json.loads(receipt)
    path = tmp_path / "receipt.json"
    decoded["upstream"]["source_dataset"]["git_sha"] = "0" * 40
    path.write_bytes(_canonical(decoded) + b"\n")
    with pytest.raises(PolicyRejection, match="frozen upstream"):
        dataset.render_public_v02_dataset_provenance_record(
            path,
            upstream_object_witness_path=witness_path,
            tdd_id_list_path=id_path,
            source_dataset_path=parquet_path,
        )

    decoded = json.loads(receipt)
    decoded["dataset"]["joined_tdd_rows_sha256"] = "0" * 64
    path.write_bytes(_canonical(decoded) + b"\n")
    with pytest.raises(PolicyRejection, match="join commitment"):
        dataset.render_public_v02_dataset_provenance_record(
            path,
            upstream_object_witness_path=witness_path,
            tdd_id_list_path=id_path,
            source_dataset_path=parquet_path,
        )

    decoded = json.loads(receipt)
    decoded["dataset"]["joined_tdd_rows"][0]["tdd_membership_ordinal"] = 2
    decoded["dataset"]["joined_tdd_rows_sha256"] = hashlib.sha256(
        _canonical(decoded["dataset"]["joined_tdd_rows"])
    ).hexdigest()
    path.write_bytes(_canonical(decoded) + b"\n")
    with pytest.raises(PolicyRejection, match="joined-row identity"):
        dataset.render_public_v02_dataset_provenance_record(
            path,
            upstream_object_witness_path=witness_path,
            tdd_id_list_path=id_path,
            source_dataset_path=parquet_path,
        )

    decoded = json.loads(receipt)
    decoded["parser"]["trusted_worker_sha256"] = "0" * 64
    path.write_bytes(_canonical(decoded) + b"\n")
    with pytest.raises(PolicyRejection, match="shipped worker"):
        dataset.render_public_v02_dataset_provenance_record(
            path,
            upstream_object_witness_path=witness_path,
            tdd_id_list_path=id_path,
            source_dataset_path=parquet_path,
        )


def test_real_subprocess_receives_cleared_environment_and_bounded_protocol(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parser_python = _dedicated_python(tmp_path)
    result = _worker_result()
    payload = _canonical({"parser_protocol": dataset.PARSER_PROTOCOL, "result": result}) + b"\n"
    worker_source = (
        b"import os,sys\n"
        b"if 'REPROASSERT_TEST_SECRET' in os.environ: raise SystemExit(9)\n"
        b"sys.stdout.buffer.write(" + repr(payload).encode() + b")\n"
    )
    monkeypatch.setenv("REPROASSERT_TEST_SECRET", "must-not-cross")
    observed = dataset._run_worker(parser_python, worker_source, b"not-parquet")
    assert observed == result
    assert dataset._validate_worker_result(observed) == result["rows"]


def test_real_subprocess_enforces_timeout_and_output_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parser_python = _dedicated_python(tmp_path)
    monkeypatch.setattr(dataset, "_WORKER_TIMEOUT_SECONDS", 0.05)
    with pytest.raises(PolicyRejection, match="time limit"):
        dataset._run_worker(parser_python, b"while True: pass\n", b"x")
    monkeypatch.setattr(dataset, "_WORKER_TIMEOUT_SECONDS", 5)
    too_much = dataset._MAX_WORKER_OUTPUT_BYTES + 1
    with pytest.raises(PolicyRejection, match="byte limit"):
        dataset._run_worker(
            parser_python,
            f"import sys\nsys.stdout.buffer.write(b'x' * {too_much})\n".encode(),
            b"x",
        )


def test_parser_python_must_be_separate_absolute_executable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with pytest.raises(PolicyRejection, match="absolute"):
        dataset._require_dedicated_parser_python(Path("python"))
    missing = tmp_path / "missing" / "bin" / "python"
    with pytest.raises(PolicyRejection, match="unavailable"):
        dataset._require_dedicated_parser_python(missing)
    current_venv = tmp_path / "current-venv"
    current_python = current_venv / "bin" / "python"
    current_python.parent.mkdir(parents=True)
    current_python.write_bytes(b"fixture")
    current_python.chmod(0o700)
    (current_venv / "pyvenv.cfg").write_text("home = /trusted\n")
    monkeypatch.setattr(dataset.sys, "prefix", str(current_venv))
    with pytest.raises(PolicyRejection, match="separately supplied"):
        dataset._require_dedicated_parser_python(current_python)


class _FakeField:
    def __init__(self, name: str, *, nullable: bool = True, kind: str = "string") -> None:
        self.name = name
        self.nullable = nullable
        self.type = kind


class _FakeTable:
    def __init__(self, rows: list[dict[str, str]]) -> None:
        self._rows = rows
        self.num_rows = len(rows)
        self.num_columns = len(parquet_worker.COLUMNS)

    def to_pylist(self) -> list[dict[str, str]]:
        return self._rows


class _FakeParquetFile:
    def __init__(self, rows: list[dict[str, str]]) -> None:
        self.metadata = SimpleNamespace(
            num_rows=parquet_worker.ROW_COUNT,
            num_row_groups=parquet_worker.ROW_GROUP_COUNT,
            num_columns=len(parquet_worker.COLUMNS),
            created_by=parquet_worker.PARQUET_CREATED_BY,
        )
        self.schema_arrow = _FakeSchema(_FakeField(name) for name in parquet_worker.COLUMNS)
        self._table = _FakeTable(rows)

    def read(self, *, use_threads: bool) -> _FakeTable:
        assert use_threads is False
        return self._table


def _fake_parquet_rows() -> list[dict[str, str]]:
    return [
        {
            name: (
                f"owner__repo-{ordinal + 1}"
                if name == "instance_id"
                else "owner/repo"
                if name == "repo"
                else "a" * 40
                if name == "base_commit"
                else f"{name}-{ordinal}"
            )
            for name in parquet_worker.COLUMNS
        }
        for ordinal in range(parquet_worker.ROW_COUNT)
    ]


class _FakeSchema(list[_FakeField]):
    @property
    def names(self) -> list[str]:
        return [field.name for field in self]


def test_worker_derives_exact_transform_commitments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("REPROASSERT_DATASET_CONTAINER", "attested-v1")
    content = b"synthetic-parquet"
    path = tmp_path / "0000.parquet"
    path.write_bytes(content)
    monkeypatch.setattr(parquet_worker, "PARQUET_BYTES", len(content))
    monkeypatch.setattr(parquet_worker, "PARQUET_SHA256", hashlib.sha256(content).hexdigest())
    rows = _fake_parquet_rows()
    fake_file = _FakeParquetFile(rows)
    fake_file.schema_arrow = _FakeSchema(_FakeField(name) for name in parquet_worker.COLUMNS)
    fake_pa = SimpleNamespace(
        __version__=parquet_worker.PYARROW_VERSION,
        __file__=str(Path(sys.prefix) / "lib/python/site-packages/pyarrow/__init__.py"),
        BufferReader=lambda value: value,
    )
    fake_pq = SimpleNamespace(ParquetFile=lambda _reader: fake_file)
    monkeypatch.setattr(
        importlib, "import_module", lambda name: fake_pa if name == "pyarrow" else fake_pq
    )

    result = parquet_worker._derive(path)
    assert result["row_count"] == 500
    commitments = cast(list[dict[str, object]], result["rows"])
    assert commitments[0]["row_ordinal"] == 0
    transformed = {
        name: rows[0][name]
        for name in parquet_worker.COLUMNS
        if name not in parquet_worker.DROP_COLUMNS
    }
    assert (
        commitments[0]["row_sha256"] == hashlib.sha256(_canonical(transformed) + b"\n").hexdigest()
    )


def test_worker_rejects_wrong_bytes_version_schema_and_duplicate_ids(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("REPROASSERT_DATASET_CONTAINER", "attested-v1")
    path = tmp_path / "0000.parquet"
    path.write_bytes(b"bad")
    with pytest.raises(ValueError, match="identity"):
        parquet_worker._read_exact(path)

    content = b"synthetic-parquet"
    path.write_bytes(content)
    monkeypatch.setattr(parquet_worker, "PARQUET_BYTES", len(content))
    monkeypatch.setattr(parquet_worker, "PARQUET_SHA256", hashlib.sha256(content).hexdigest())
    fake_pa = SimpleNamespace(__version__="23.0.0", __file__=__file__, BufferReader=lambda x: x)
    monkeypatch.setattr(importlib, "import_module", lambda _name: fake_pa)
    with pytest.raises(ValueError, match="version"):
        parquet_worker._derive(path)

    rows = _fake_parquet_rows()
    rows[-1]["instance_id"] = rows[0]["instance_id"]
    fake_file = _FakeParquetFile(rows)
    fake_file.schema_arrow = _FakeSchema(_FakeField(name) for name in parquet_worker.COLUMNS)
    good_pa = SimpleNamespace(
        __version__=parquet_worker.PYARROW_VERSION,
        __file__=str(Path(sys.prefix) / "lib/python/site-packages/pyarrow/__init__.py"),
        BufferReader=lambda value: value,
    )
    fake_pq = SimpleNamespace(ParquetFile=lambda _reader: fake_file)
    monkeypatch.setattr(
        importlib, "import_module", lambda name: good_pa if name == "pyarrow" else fake_pq
    )
    with pytest.raises(ValueError, match="duplicated"):
        parquet_worker._derive(path)


def test_worker_leak_audit_rejects_fix_reference_and_indented_oracle_lines() -> None:
    leaked = "return the exact forty character oracle-bearing value here"
    row = {
        "instance_id": "owner__repo-42",
        "patch": f"@@ -1 +1 @@\n+    {leaked}\n",
        "problem_statement": f"Observed snippet:\n    {leaked}\n",
        "repo": "owner/repo",
        "test_patch": "",
    }
    assert parquet_worker._audit_row(row) == (False, True, False)
    row["problem_statement"] = "See https://github.com/owner/repo/pull/42 for the fix"
    assert parquet_worker._audit_row(row)[0] is True
    row["problem_statement"] = "This was also discussed in #42"
    assert parquet_worker._audit_row(row)[0] is True


def test_worker_main_is_canonical_and_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    output = io.BytesIO()
    monkeypatch.setattr(parquet_worker, "_set_resource_limits", lambda: None)
    monkeypatch.setattr(parquet_worker, "_derive", lambda _path, _requested: {"ok": True})
    monkeypatch.setattr(sys, "argv", ["worker.py", "data.parquet"])
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=output))
    assert parquet_worker.main() == 0
    assert (
        output.getvalue()
        == _canonical({"parser_protocol": parquet_worker.PARSER_PROTOCOL, "result": {"ok": True}})
        + b"\n"
    )
    monkeypatch.setattr(
        parquet_worker,
        "_derive",
        lambda _path, _requested: (_ for _ in ()).throw(ValueError("no")),
    )
    assert parquet_worker.main() == 1
    monkeypatch.setattr(sys, "argv", ["worker.py"])
    assert parquet_worker.main() == 2


def test_worker_macos_keeps_non_memory_resource_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    applied: list[tuple[int, tuple[int, int]]] = []
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(
        resource,
        "getrlimit",
        lambda _kind: (resource.RLIM_INFINITY,) * 2,
    )
    monkeypatch.setattr(
        resource,
        "setrlimit",
        lambda kind, value: applied.append((kind, value)),
    )

    parquet_worker._set_resource_limits()

    applied_kinds = {kind for kind, _ in applied}
    assert applied_kinds == {
        resource.RLIMIT_CORE,
        resource.RLIMIT_CPU,
        resource.RLIMIT_FSIZE,
        resource.RLIMIT_NOFILE,
    }


@pytest.mark.skipif(
    not (
        Path("/tmp/reproassert-upstream/id_list.txt").is_file()
        and Path("/tmp/reproassert-upstream/0000.parquet").is_file()
        and Path("/tmp/reproassert-pyarrow24/bin/python").exists()
    ),
    reason="authentic frozen artifacts and separately supplied pyarrow 24 venv are unavailable",
)
def test_authentic_frozen_dataset_receipt_and_join(tmp_path: Path) -> None:
    upstream_root = Path("/tmp/reproassert-upstream").resolve(strict=True)
    parser_root = Path("/tmp/reproassert-pyarrow24").resolve(strict=True)
    receipt = dataset.render_private_v02_dataset_parser_receipt(
        tdd_id_list_path=upstream_root / "id_list.txt",
        source_dataset_path=upstream_root / "0000.parquet",
        upstream_object_witness_path=Path(
            "benchmarks/v0.2-draft/upstream-object-witness.json"
        ).resolve(strict=True),
        parser_python=parser_root / "bin/python",
    )
    parsed = json.loads(receipt)
    assert parsed["dataset"]["row_count"] == 500
    assert parsed["dataset"]["column_count"] == 13
    assert parsed["dataset"]["unique_instance_id_count"] == 500
    assert parsed["dataset"]["joined_tdd_row_count"] == 449
    assert len(parsed["dataset"]["joined_tdd_rows"]) == 449
    assert parsed["parser"]["pyarrow_version"] == "24.0.0"
    receipt_path = tmp_path / "private-receipt.json"
    receipt_path.write_bytes(receipt)
    public = json.loads(
        dataset.render_public_v02_dataset_provenance_record(
            receipt_path,
            upstream_object_witness_path=Path(
                "benchmarks/v0.2-draft/upstream-object-witness.json"
            ).resolve(strict=True),
            tdd_id_list_path=upstream_root / "id_list.txt",
            source_dataset_path=upstream_root / "0000.parquet",
        )
    )
    assert public["dataset_checks"]["joined_tdd_row_count"] == 449
