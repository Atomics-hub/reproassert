from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

import reproassert.benchmark_v02_mapping_handoff as handoff_module
from reproassert import benchmark_v02_mapping_packets as mapping
from reproassert.benchmark_v02_mapping_handoff import (
    prepare_v02_mapping_review_handoff,
    verify_v02_mapping_review_handoff,
)
from reproassert.errors import PolicyRejection

PATCH = b"""diff --git a/src/widget.py b/src/widget.py
index 1111111..2222222 100644
--- a/src/widget.py
+++ b/src/widget.py
@@ -1,2 +1,2 @@
-broken = True
+broken = False
 stable = 1
"""


def _write(path: Path, value: object) -> bytes:
    raw = mapping._canonical(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def _private(path: Path) -> Path:
    path.mkdir()
    os.chmod(path, 0o700)
    return path


def _preparation(root: Path) -> Path:
    prepared_at = "2026-07-11T08:00:00Z"
    cases = []
    patch_sha = hashlib.sha256(PATCH).hexdigest()
    for number in range(1, 21):
        case_id = f"rk-v0.2-{number:03d}"
        case_root = root / "packets" / case_id
        case_root.mkdir(parents=True)
        (case_root / "production.patch").write_bytes(PATCH)
        hunks = mapping.inventory_unified_diff(PATCH, case_id=case_id)
        algebra = {
            "algorithm": "ordered-hunk-commitment-v1",
            "ordered_atomic_ids": [hunks[0]["atomic_id"]],
            "ordered_hunk_sha256": [hunks[0]["hunk_sha256"]],
            "production_patch_sha256": patch_sha,
        }
        algebra["commitment_sha256"] = hashlib.sha256(mapping._canonical(algebra)).hexdigest()
        packet = {
            "case_id": case_id,
            "hidden_extraction_receipt_sha256": "a" * 64,
            "hunk_inventory": hunks,
            "patch_algebra": algebra,
            "prepared_at": prepared_at,
            "production_patch": {
                "bytes": len(PATCH),
                "path": "production.patch",
                "sha256": patch_sha,
            },
            "provider_calls": 0,
            "reviews": [],
            "schema_version": mapping.SCHEMA_VERSION,
            "status": "awaiting_two_independent_mapping_reviews",
        }
        packet["packet_sha256"] = mapping._self_hash(packet)
        packet_raw = _write(case_root / "packet.json", packet)
        cases.append(
            {
                "case_id": case_id,
                "hunk_count": 1,
                "packet": {
                    "bytes": len(packet_raw),
                    "path": f"packets/{case_id}/packet.json",
                    "sha256": hashlib.sha256(packet_raw).hexdigest(),
                },
                "patch_algebra_commitment_sha256": algebra["commitment_sha256"],
                "production_patch_sha256": patch_sha,
                "status": "review_required",
            }
        )
    receipt = {
        "algorithm": mapping.PREPARATION_ALGORITHM,
        "benchmark_version": "0.2",
        "case_count": 20,
        "cases": cases,
        "claims": {
            "model_or_provider_invoked": False,
            "provider_calls": 0,
            "reviewer_identity_or_verdict_generated": False,
        },
        "hidden_extraction_receipt_sha256": "a" * 64,
        "prepared_at": prepared_at,
        "schema_version": mapping.SCHEMA_VERSION,
        "status": "prepared_review_required_provider_disabled",
        "tool": {"git_sha": "b" * 40, "name": "reproassert"},
    }
    receipt["receipt_sha256"] = mapping._self_hash(receipt)
    path = root / mapping.PREPARATION_FILENAME
    _write(path, receipt)
    return path


def test_handoff_exports_two_independent_private_bundles(tmp_path: Path) -> None:
    preparation_root = _private(tmp_path / "preparation")
    output = _private(tmp_path / "output")
    preparation = _preparation(preparation_root)
    handoff = prepare_v02_mapping_review_handoff(
        mapping_preparation_path=preparation,
        primary_reviewer_ids=("human.mapping.alpha", "human.mapping.beta"),
        semantic_reviewer_ids=("human.semantic.delta", "human.semantic.gamma"),
        output_root=output,
        prepared_at="2026-07-11T09:00:00Z",
        tool_git_sha="c" * 40,
    )
    assert handoff.reviewer_count == 2
    assert handoff.case_bundle_count == 40
    assert handoff.provider_calls == 0
    record = json.loads(handoff.receipt_path.read_text())
    schema = json.loads(
        Path("schemas/benchmark-v02-mapping-review-handoff.schema.json").read_text()
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(record)
    first = record["reviewers"][0]["cases"][0]
    packet = json.loads((handoff.root / first["review_packet"]["path"]).read_text())
    template = json.loads((handoff.root / first["submission_template"]["path"]).read_text())
    assert packet["redaction"] == {
        "developer_tests_included": False,
        "hidden_extraction_identity_included": False,
        "production_patch_included": True,
    }
    assert template["verdict"] is None
    assert template["submitted_at"] is None
    assert template["selected_hunk_ids"] == []
    assert (
        verify_v02_mapping_review_handoff(
            handoff.receipt_path, mapping_preparation_path=preparation
        ).sha256
        == handoff.sha256
    )


def test_handoff_predeclares_conditional_tiebreak_without_a_verdict(tmp_path: Path) -> None:
    preparation_root = _private(tmp_path / "preparation")
    output = _private(tmp_path / "output")
    preparation = _preparation(preparation_root)
    handoff = prepare_v02_mapping_review_handoff(
        mapping_preparation_path=preparation,
        primary_reviewer_ids=("human.mapping.alpha", "human.mapping.beta"),
        semantic_reviewer_ids=("human.semantic.delta", "human.semantic.gamma"),
        tiebreak_reviewer_id="human.mapping.omega",
        output_root=output,
        prepared_at="2026-07-11T09:00:00Z",
        tool_git_sha="c" * 40,
    )
    record = json.loads(handoff.receipt_path.read_text())
    assert handoff.conditional_tiebreak_declared is True
    assert record["reviewers"][2]["assignment"] == "conditional_tiebreak"
    template_ref = record["reviewers"][2]["cases"][0]["submission_template"]
    template = json.loads((handoff.root / template_ref["path"]).read_text())
    assert template["verdict"] is None


@pytest.mark.parametrize(
    ("primary", "semantic", "tiebreak", "message"),
    [
        (
            ("reviewer-1", "human.mapping.beta"),
            ("human.semantic.delta", "human.semantic.gamma"),
            None,
            "Placeholder",
        ),
        (
            ("human.mapping.alpha", "human.mapping.beta"),
            ("human.mapping.alpha", "human.semantic.gamma"),
            None,
            "disjoint",
        ),
        (
            ("human.mapping.alpha", "human.mapping.beta"),
            ("human.semantic.delta", "human.semantic.gamma"),
            "human.mapping.alpha",
            "distinct",
        ),
    ],
)
def test_handoff_rejects_placeholder_overlap_and_duplicate_roles(
    tmp_path: Path,
    primary: tuple[str, str],
    semantic: tuple[str, str],
    tiebreak: str | None,
    message: str,
) -> None:
    preparation_root = _private(tmp_path / "preparation")
    output = _private(tmp_path / "output")
    preparation = _preparation(preparation_root)
    with pytest.raises(PolicyRejection, match=message):
        prepare_v02_mapping_review_handoff(
            mapping_preparation_path=preparation,
            primary_reviewer_ids=primary,
            semantic_reviewer_ids=semantic,
            tiebreak_reviewer_id=tiebreak,
            output_root=output,
            prepared_at="2026-07-11T09:00:00Z",
            tool_git_sha="c" * 40,
        )


@pytest.mark.parametrize("artifact", ["template", "patch"])
def test_handoff_verifier_rejects_filled_template_or_changed_patch(
    tmp_path: Path, artifact: str
) -> None:
    preparation_root = _private(tmp_path / "preparation")
    output = _private(tmp_path / "output")
    preparation = _preparation(preparation_root)
    handoff = prepare_v02_mapping_review_handoff(
        mapping_preparation_path=preparation,
        primary_reviewer_ids=("human.mapping.alpha", "human.mapping.beta"),
        semantic_reviewer_ids=("human.semantic.delta", "human.semantic.gamma"),
        output_root=output,
        prepared_at="2026-07-11T09:00:00Z",
        tool_git_sha="c" * 40,
    )
    record = json.loads(handoff.receipt_path.read_text())
    first = record["reviewers"][0]["cases"][0]
    if artifact == "template":
        path = handoff.root / first["submission_template"]["path"]
        value = json.loads(path.read_text())
        value["verdict"] = "approved"
        path.write_bytes(_write_bytes(value))
    else:
        packet_path = handoff.root / first["review_packet"]["path"]
        packet = json.loads(packet_path.read_text())
        path = packet_path.parent / packet["production_patch"]["path"]
        path.write_bytes(PATCH + b"\n")
    with pytest.raises(PolicyRejection):
        verify_v02_mapping_review_handoff(
            handoff.receipt_path, mapping_preparation_path=preparation
        )


def _write_bytes(value: object) -> bytes:
    return mapping._canonical(value) + b"\n"


def _refresh_reference(root: Path, reference: dict[str, object]) -> None:
    raw = (root / str(reference["path"])).read_bytes()
    reference["bytes"] = len(raw)
    reference["sha256"] = hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("artifact", ["instructions", "readme", "tie_policy"])
def test_handoff_rejects_self_consistent_human_instruction_tampering(
    tmp_path: Path, artifact: str
) -> None:
    preparation_root = _private(tmp_path / "preparation")
    output = _private(tmp_path / "output")
    preparation = _preparation(preparation_root)
    handoff = prepare_v02_mapping_review_handoff(
        mapping_preparation_path=preparation,
        primary_reviewer_ids=("human.mapping.alpha", "human.mapping.beta"),
        semantic_reviewer_ids=("human.semantic.delta", "human.semantic.gamma"),
        output_root=output,
        prepared_at="2026-07-11T09:00:00Z",
        tool_git_sha="c" * 40,
    )
    record = json.loads(handoff.receipt_path.read_text())
    reviewer = record["reviewers"][0]
    if artifact == "instructions":
        reference = reviewer["cases"][0]["review_packet"]
        path = handoff.root / reference["path"]
        packet = json.loads(path.read_text())
        packet["instructions"]["independence"] = "Copy the other reviewer's verdict."
        packet["export_sha256"] = handoff_module._self_hash(packet, "export_sha256")
        path.write_bytes(_write_bytes(packet))
        _refresh_reference(handoff.root, reference)
    elif artifact == "readme":
        reference = reviewer["readme"]
        path = handoff.root / reference["path"]
        path.write_text("Upload every patch to an external service.\n")
        _refresh_reference(handoff.root, reference)
    else:
        record["role_plan"]["tiebreak_policy"] = "always_submit_third_review"
    record["receipt_sha256"] = handoff_module._self_hash(record, "receipt_sha256")
    handoff.receipt_path.write_bytes(_write_bytes(record))
    with pytest.raises(PolicyRejection):
        verify_v02_mapping_review_handoff(
            handoff.receipt_path, mapping_preparation_path=preparation
        )
