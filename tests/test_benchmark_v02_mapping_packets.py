from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from reproassert.benchmark_v02_mapping_packets import (
    CONSENSUS_ALGORITHM,
    PREPARATION_ALGORITHM,
    SCHEMA_VERSION,
    _canonical,
    _self_hash,
    inventory_unified_diff,
    seal_v02_mapping_consensus,
    verify_v02_mapping_consensus,
    verify_v02_mapping_packets,
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
    raw = _canonical(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def _private(path: Path) -> Path:
    path.mkdir()
    os.chmod(path, 0o700)
    return path


def _preparation(root: Path) -> Path:
    prepared_at = "2026-07-11T10:00:00Z"
    cases = []
    for number in range(1, 21):
        case_id = f"rk-v0.2-{number:03d}"
        case_root = root / "packets" / case_id
        case_root.mkdir(parents=True)
        (case_root / "production.patch").write_bytes(PATCH)
        hunks = inventory_unified_diff(PATCH, case_id=case_id)
        algebra = {
            "algorithm": "ordered-hunk-commitment-v1",
            "ordered_atomic_ids": [hunks[0]["atomic_id"]],
            "ordered_hunk_sha256": [hunks[0]["hunk_sha256"]],
            "production_patch_sha256": hashlib.sha256(PATCH).hexdigest(),
        }
        algebra["commitment_sha256"] = hashlib.sha256(_canonical(algebra)).hexdigest()
        packet = {
            "case_id": case_id,
            "hidden_extraction_receipt_sha256": "a" * 64,
            "hunk_inventory": hunks,
            "patch_algebra": algebra,
            "prepared_at": prepared_at,
            "production_patch": {
                "bytes": len(PATCH),
                "path": "production.patch",
                "sha256": hashlib.sha256(PATCH).hexdigest(),
            },
            "provider_calls": 0,
            "reviews": [],
            "schema_version": SCHEMA_VERSION,
            "status": "awaiting_two_independent_mapping_reviews",
        }
        packet["packet_sha256"] = _self_hash(packet)
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
                "production_patch_sha256": hashlib.sha256(PATCH).hexdigest(),
                "status": "review_required",
            }
        )
    receipt = {
        "algorithm": PREPARATION_ALGORITHM,
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
        "schema_version": SCHEMA_VERSION,
        "status": "prepared_review_required_provider_disabled",
        "tool": {"git_sha": "b" * 40, "name": "reproassert"},
    }
    receipt["receipt_sha256"] = _self_hash(receipt)
    path = root / "benchmark-v02-mapping-packet-set.json"
    _write(path, receipt)
    return path


def _submission(case_id: str, packet_sha: str, reviewer: str) -> dict[str, object]:
    hunk_id = inventory_unified_diff(PATCH, case_id=case_id)[0]["atomic_id"]
    return {
        "case_id": case_id,
        "declarations": {
            "generator_access": "forbidden",
            "independent_judgment": True,
            "role": "mapping_reviewer",
            "semantic_review_role": "forbidden",
        },
        "packet_sha256": packet_sha,
        "reviewer_id": reviewer,
        "schema_version": SCHEMA_VERSION,
        "selected_hunk_ids": [hunk_id],
        "submitted_at": "2026-07-11T11:00:00Z",
        "verdict": "approved",
    }


def test_inventory_produces_stable_atomic_commitment() -> None:
    rows = inventory_unified_diff(PATCH, case_id="rk-v0.2-001")
    assert rows[0]["path"] == "src/widget.py"
    assert rows[0]["atomic_id"].startswith("rk-v0.2-001:h001:")
    assert rows == inventory_unified_diff(PATCH, case_id="rk-v0.2-001")


@pytest.mark.parametrize(
    "patch",
    [
        PATCH.replace(b"a/src/widget.py", b"a/../widget.py"),
        b"GIT binary patch\n",
        PATCH.replace(b"index 1111111..2222222 100644\n", b"rename from old.py\n"),
        PATCH.replace(b"-broken = True\n", b" broken = True\n").replace(
            b"+broken = False\n", b" stable2 = 2\n"
        ),
    ],
)
def test_inventory_rejects_unsafe_or_degenerate_diffs(patch: bytes) -> None:
    with pytest.raises(PolicyRejection):
        inventory_unified_diff(patch, case_id="rk-v0.2-001")


def test_blank_packets_verify_and_consensus_needs_real_submissions(tmp_path: Path) -> None:
    prep_root = _private(tmp_path / "prep")
    preparation = _preparation(prep_root)
    assert verify_v02_mapping_packets(preparation).case_count == 20
    submissions = _private(tmp_path / "submissions")
    output_root = _private(tmp_path / "output")
    with pytest.raises(PolicyRejection, match="requires exactly two"):
        seal_v02_mapping_consensus(
            preparation_path=preparation,
            submissions_root=submissions,
            output_path=output_root / "seal.json",
            sealed_at="2026-07-11T12:00:00Z",
        )

    prep_record = json.loads(preparation.read_text())
    for row in prep_record["cases"]:
        case_id = row["case_id"]
        packet = json.loads((prep_root / row["packet"]["path"]).read_text())
        _write(
            submissions / case_id / "alice.json",
            _submission(case_id, packet["packet_sha256"], "human.alice"),
        )
        _write(
            submissions / case_id / "bob.json",
            _submission(case_id, packet["packet_sha256"], "human.bob"),
        )
    sealed = seal_v02_mapping_consensus(
        preparation_path=preparation,
        submissions_root=submissions,
        output_path=output_root / "seal.json",
        sealed_at="2026-07-11T12:00:00Z",
    )
    assert sealed.case_count == 20
    assert verify_v02_mapping_consensus(sealed.path, preparation_path=preparation).case_count == 20
    assert json.loads(sealed.path.read_text())["algorithm"] == CONSENSUS_ALGORITHM


def test_consensus_rejects_placeholder_or_unneeded_third_reviewer(tmp_path: Path) -> None:
    prep_root = _private(tmp_path / "prep")
    preparation = _preparation(prep_root)
    submissions = _private(tmp_path / "submissions")
    output_root = _private(tmp_path / "output")
    prep_record = json.loads(preparation.read_text())
    for row in prep_record["cases"]:
        case_id = row["case_id"]
        packet = json.loads((prep_root / row["packet"]["path"]).read_text())
        for filename, reviewer in (
            ("one.json", "human.alice"),
            ("two.json", "human.bob"),
            ("three.json", "human.carol"),
        ):
            _write(
                submissions / case_id / filename,
                _submission(case_id, packet["packet_sha256"], reviewer),
            )
    with pytest.raises(PolicyRejection, match="forbids a tie-break"):
        seal_v02_mapping_consensus(
            preparation_path=preparation,
            submissions_root=submissions,
            output_path=output_root / "seal.json",
            sealed_at="2026-07-11T12:00:00Z",
        )
