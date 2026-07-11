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
