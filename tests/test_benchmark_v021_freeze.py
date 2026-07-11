from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from reproassert.benchmark_v02_preparation import _image_id
from reproassert.benchmark_v021_freeze import (
    LEGACY_IMAGE_ID,
    PARSER_RECEIPT_SHA256,
    SUCCESSOR_IMAGE_ID,
    load_v021_preparation_freeze,
)
from reproassert.errors import PolicyRejection
from reproassert.schema import schema_text

ROOT = Path(__file__).parents[1]
FREEZE = ROOT / "benchmarks/v0.2-draft/preparation-freeze-v0.2.1.json"
SCHEMA = ROOT / "schemas/benchmark-v021-preparation-freeze.schema.json"


def test_successor_freeze_is_canonical_schema_valid_and_cross_bound() -> None:
    record = json.loads(FREEZE.read_text())
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(record)

    loaded = load_v021_preparation_freeze(FREEZE, repository_root=ROOT)
    assert loaded.case_count == 20
    assert loaded.image_id == SUCCESSOR_IMAGE_ID
    assert loaded.parser_receipt_sha256 == PARSER_RECEIPT_SHA256
    assert record["claims"]["historical_artifacts_rewritten"] is False
    assert record["claims"]["provider_calls"] == 0


def test_successor_freeze_fails_closed_on_self_or_predecessor_tampering(tmp_path: Path) -> None:
    changed = json.loads(FREEZE.read_text())
    changed["claims"]["results_changed"] = True
    tampered_freeze = tmp_path / "freeze.json"
    tampered_freeze.write_text(json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(PolicyRejection, match="identity"):
        load_v021_preparation_freeze(tampered_freeze)

    fake_root = tmp_path / "repo"
    (fake_root / "benchmarks/v0.2-draft").mkdir(parents=True)
    for name in (
        "selection-freeze.json",
        "dataset-parser-boundary-attestation.json",
        "leak-audited-cohort-plan.json",
    ):
        (fake_root / "benchmarks/v0.2-draft" / name).write_text("tampered\n")
    with pytest.raises(PolicyRejection, match="predecessor"):
        load_v021_preparation_freeze(FREEZE, repository_root=fake_root)


def test_image_trust_is_append_only_and_schema_is_bundled() -> None:
    assert _image_id(LEGACY_IMAGE_ID) == LEGACY_IMAGE_ID
    assert _image_id(SUCCESSOR_IMAGE_ID) == SUCCESSOR_IMAGE_ID
    with pytest.raises(PolicyRejection, match="append-only trusted image set"):
        _image_id("sha256:" + "f" * 64)
    assert schema_text("benchmark-v021-preparation-freeze") == SCHEMA.read_text()
    bundled = ROOT / "src/reproassert/schemas/benchmark-v021-preparation-freeze.schema.json"
    assert SCHEMA.read_bytes() == bundled.read_bytes()
