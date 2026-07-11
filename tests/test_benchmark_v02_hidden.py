from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator

import reproassert._benchmark_v02_hidden_worker as worker
import reproassert.benchmark_v02_hidden as hidden
from reproassert.errors import PolicyRejection

PRODUCTION = b"SECRET production patch\n"
DEVELOPER = b"SECRET developer tests\n"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _plan() -> dict[str, object]:
    return {
        "cohort_plan_sha256": hidden.FROZEN_V02_COHORT_PLAN_SHA256,
        "cases": [
            {
                "base_sha": f"{ordinal:040x}",
                "case_id": f"rk-v0.2-{ordinal:03d}",
                "instance_id": f"owner__repo-{ordinal}",
                "repo": "owner/repo",
                "source_dataset_row_ordinal": ordinal - 1,
            }
            for ordinal in range(1, 21)
        ],
    }


def _fake_output(request: bytes, created: list[Path]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="hidden-test-output-")).resolve(strict=True)
    os.chmod(root, 0o700)
    rows: list[dict[str, object]] = []
    for ordinal, case in enumerate(cast(list[dict[str, object]], _plan()["cases"]), 1):
        case_id = cast(str, case["case_id"])
        case_root = root / case_id
        case_root.mkdir(mode=0o700)
        metadata = _canonical(
            {
                "base_commit": case["base_sha"],
                "case_id": case_id,
                "created_at": "2020-01-01T00:00:00Z",
                "difficulty": "<15 min fix",
                "environment_setup_commit": f"{ordinal + 100:040x}",
                "instance_id": case["instance_id"],
                "repo": case["repo"],
                "source_dataset_row_ordinal": ordinal - 1,
                "source_row_sha256": f"{ordinal:064x}",
                "version": "1.0",
            }
        )
        artifacts = {
            "production.patch": PRODUCTION,
            "developer-tests.patch": DEVELOPER,
            "metadata.json": metadata,
        }
        for name, content in artifacts.items():
            (case_root / name).write_bytes(content)
            os.chmod(case_root / name, 0o600)
        rows.append(
            {
                "case_id": case_id,
                "developer_tests_bytes": len(DEVELOPER),
                "developer_tests_sha256": hashlib.sha256(DEVELOPER).hexdigest(),
                "metadata_bytes": len(metadata),
                "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                "production_patch_bytes": len(PRODUCTION),
                "production_patch_sha256": hashlib.sha256(PRODUCTION).hexdigest(),
            }
        )
    (root / "manifest.json").write_bytes(
        _canonical(
            {
                "artifacts": rows,
                "case_count": 20,
                "protocol": hidden.HIDDEN_WORKER_PROTOCOL,
                "request_sha256": hashlib.sha256(request).hexdigest(),
            }
        )
    )
    os.chmod(root / "manifest.json", 0o600)
    created.append(root)
    return root


def _install_fakes(monkeypatch: pytest.MonkeyPatch, created: list[Path]) -> bytes:
    dataset = b"pinned fixture"
    monkeypatch.setattr(hidden, "SOURCE_DATASET_BYTES", len(dataset))
    monkeypatch.setattr(hidden, "SOURCE_DATASET_SHA256", hashlib.sha256(dataset).hexdigest())
    monkeypatch.setattr(hidden, "load_v02_leak_audited_cohort_plan", lambda _path: _plan())

    def run(**kwargs: object) -> tuple[Path, str]:
        request_path = cast(Path, kwargs["request_path"])
        return _fake_output(request_path.read_bytes(), created), "a" * 64

    monkeypatch.setattr(hidden, "_run_hidden_container", run)
    return dataset


def test_prepare_verify_private_hidden_artifacts_without_leak(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    created: list[Path] = []
    dataset = _install_fakes(monkeypatch, created)
    source = tmp_path / "dataset.parquet"
    source.write_bytes(dataset)
    plan = tmp_path / "plan.json"
    plan.write_bytes(b"fixture plan\n")
    output = tmp_path / "private"
    output.mkdir(mode=0o700)

    result = hidden.prepare_v02_hidden_gold(
        output_root=output,
        source_dataset_path=source,
        cohort_plan_path=plan,
        image_digest=hidden.FROZEN_V02_DATASET_PARSER_IMAGE_ID,
        prepared_at="2026-07-11T00:00:00Z",
    )

    assert result.case_count == 20
    assert result.provider_calls == 0
    assert all(not path.exists() for path in created)
    receipt = result.receipt_path.read_bytes()
    assert PRODUCTION not in receipt and DEVELOPER not in receipt
    assert "SECRET" not in repr(result)
    schema = json.loads(Path("schemas/benchmark-v02-hidden-extraction.schema.json").read_text())
    assert (
        Path("schemas/benchmark-v02-hidden-extraction.schema.json").read_bytes()
        == Path("src/reproassert/schemas/benchmark-v02-hidden-extraction.schema.json").read_bytes()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(receipt))
    verified = hidden.verify_v02_hidden_gold(result.receipt_path)
    refs = hidden.hidden_case_artifacts(verified, "rk-v0.2-001")
    assert set(refs) == {"developer_tests", "metadata", "production_patch"}
    assert refs["production_patch"]["path"] == (
        result.root / "artifacts/rk-v0.2-001/production.patch"
    )
    assert oct(result.root.stat().st_mode & 0o777) == "0o700"
    assert oct(cast(Path, refs["production_patch"]["path"]).stat().st_mode & 0o777) == "0o600"

    assert verified.prepared == result
    assert all(not path.exists() for path in created)

    result.receipt_path.write_bytes(result.receipt_path.read_bytes() + b" ")
    with pytest.raises(PolicyRejection, match="changed after verification"):
        hidden.hidden_case_artifacts(verified, "rk-v0.2-001")


def test_verification_rejects_hidden_tamper_and_worker_substitution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    created: list[Path] = []
    dataset = _install_fakes(monkeypatch, created)
    source = tmp_path / "dataset.parquet"
    source.write_bytes(dataset)
    plan = tmp_path / "plan.json"
    plan.write_bytes(b"fixture plan\n")
    output = tmp_path / "private"
    output.mkdir(mode=0o700)
    result = hidden.prepare_v02_hidden_gold(
        output_root=output,
        source_dataset_path=source,
        cohort_plan_path=plan,
        image_digest=hidden.FROZEN_V02_DATASET_PARSER_IMAGE_ID,
        prepared_at="2026-07-11T00:00:00Z",
    )
    production = result.root / "artifacts/rk-v0.2-001/production.patch"
    production.write_bytes(b"tampered")
    with pytest.raises(PolicyRejection, match="commitment"):
        hidden.verify_v02_hidden_gold(result.receipt_path)
    production.write_bytes(PRODUCTION)
    worker_path = result.root / "inputs/worker.py"
    worker_path.write_bytes(b"# substituted worker\n")
    with pytest.raises(PolicyRejection, match=r"commitment|trusted worker"):
        hidden.verify_v02_hidden_gold(result.receipt_path)


def test_worker_failure_is_silent(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(worker, "_limits", lambda: None)
    monkeypatch.setattr(
        worker, "_derive", lambda *_args: (_ for _ in ()).throw(ValueError(PRODUCTION))
    )
    monkeypatch.setattr(worker.sys, "argv", ["worker", "dataset", "request", "output"])
    assert worker.main() == 1
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


def test_worker_main_success_usage_and_text_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker.sys, "argv", ["worker"])
    assert worker.main() == 2
    called: list[tuple[Path, Path, Path]] = []
    monkeypatch.setattr(worker, "_limits", lambda: None)
    monkeypatch.setattr(worker, "_derive", lambda *paths: called.append(paths))
    monkeypatch.setattr(worker.sys, "argv", ["worker", "dataset", "request", "output"])
    assert worker.main() == 0
    assert called == [(Path("dataset"), Path("request"), Path("output"))]
    assert worker._text("value", "field", allow_empty=False, maximum=5) == b"value"
    with pytest.raises(ValueError, match="type mismatch"):
        worker._text(None, "field", allow_empty=True, maximum=5)
    with pytest.raises(ValueError, match="size mismatch"):
        worker._text("", "field", allow_empty=False, maximum=5)
    with pytest.raises(ValueError, match="size mismatch"):
        worker._text("longer", "field", allow_empty=True, maximum=5)


def test_worker_request_rejects_wrong_count_and_repeated_instances(tmp_path: Path) -> None:
    request = tmp_path / "request.json"
    request.write_bytes(
        worker._canonical({"cases": [], "protocol": worker.REQUEST_PROTOCOL}) + b"\n"
    )
    with pytest.raises(ValueError, match="case count mismatch"):
        worker._load_request(request)
    repeated = [
        {"case_id": f"rk-v0.2-{ordinal:03d}", "instance_id": "owner__repo-1"}
        for ordinal in range(1, 21)
    ]
    request.write_bytes(
        worker._canonical({"cases": repeated, "protocol": worker.REQUEST_PROTOCOL}) + b"\n"
    )
    with pytest.raises(ValueError, match="instances repeat"):
        worker._load_request(request)


def test_worker_derives_twenty_private_artifact_sets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dataset = b"synthetic parquet bytes"
    monkeypatch.setattr(worker, "PARQUET_BYTES", len(dataset))
    monkeypatch.setattr(worker, "PARQUET_SHA256", hashlib.sha256(dataset).hexdigest())
    dataset_path = tmp_path / "dataset.parquet"
    dataset_path.write_bytes(dataset)
    cases = [
        {
            "case_id": f"rk-v0.2-{ordinal:03d}",
            "instance_id": f"owner__repo-{ordinal}",
        }
        for ordinal in range(1, 21)
    ]
    request_path = tmp_path / "request.json"
    request_path.write_bytes(
        worker._canonical({"cases": cases, "protocol": worker.REQUEST_PROTOCOL}) + b"\n"
    )
    rows: list[dict[str, object]] = [
        {
            "base_commit": f"{ordinal:040x}",
            "created_at": "2020-01-01T00:00:00Z",
            "difficulty": "<15 min fix",
            "environment_setup_commit": f"{ordinal + 100:040x}",
            "instance_id": f"owner__repo-{ordinal}",
            "patch": f"production patch {ordinal}\n",
            "repo": "owner/repo",
            "test_patch": f"developer patch {ordinal}\n",
            "version": "1.0",
        }
        for ordinal in range(1, 21)
    ]
    rows.extend(
        {
            "instance_id": f"unused__row-{ordinal}",
        }
        for ordinal in range(21, worker.ROW_COUNT + 1)
    )

    class FakeTable:
        num_rows = worker.ROW_COUNT

        def to_pylist(self) -> list[dict[str, object]]:
            return rows

    class FakeArrow:
        __version__ = worker.PYARROW_VERSION

        @staticmethod
        def BufferReader(content: bytes) -> bytes:
            return content

    class FakeParquet:
        @staticmethod
        def read_table(_reader: bytes, *, use_threads: bool) -> FakeTable:
            assert use_threads is False
            return FakeTable()

    monkeypatch.setattr(
        worker.importlib,
        "import_module",
        lambda name: FakeArrow if name == "pyarrow" else FakeParquet,
    )
    monkeypatch.setenv("REPROASSERT_HIDDEN_CONTAINER", "attested-v1")
    output = tmp_path / "output"
    output.mkdir(mode=0o700)

    worker._derive(dataset_path, request_path, output)

    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["case_count"] == 20
    assert len(manifest["artifacts"]) == 20
    assert (output / "rk-v0.2-001/production.patch").read_text() == "production patch 1\n"
    assert (output / "rk-v0.2-020/developer-tests.patch").read_text() == ("developer patch 20\n")
    assert oct((output / "manifest.json").stat().st_mode & 0o777) == "0o600"


def test_container_contract_is_no_network_read_only_and_cap_dropped(tmp_path: Path) -> None:
    policy = hidden.DatasetParserContainerPolicy(
        image_digest=hidden.FROZEN_V02_DATASET_PARSER_IMAGE_ID
    )
    output = tmp_path / "output"
    output.mkdir()
    args = hidden._hidden_create_args("name", tmp_path, output, policy, ("-i", "command"))
    rendered = " ".join(args)
    assert "--network none" in rendered
    assert "--read-only" in args
    assert "--cap-drop ALL" in rendered
    assert "no-new-privileges=true" in rendered
    assert "dst=/input,readonly" in rendered
