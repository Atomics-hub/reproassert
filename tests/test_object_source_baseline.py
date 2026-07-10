from __future__ import annotations

import hashlib
import json
import re
import statistics
from pathlib import Path
from typing import Any

from reproassert.benchmark_object_source import OBJECT_SOURCE_POLICY_SHA256

ROOT = Path(__file__).parents[1]
BASELINE = ROOT / "benchmarks" / "v0.1" / "object-source-preparation-baseline.json"
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_OID = re.compile(r"[0-9a-f]{40}")


def _strict_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    decoded = json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    assert isinstance(decoded, dict)
    return decoded


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_object_source_baseline_is_complete_bounded_and_inert() -> None:
    baseline = _strict_json(BASELINE)
    summary = baseline["summary"]
    cases = baseline["cases"]

    assert set(baseline) == {
        "schema_version",
        "kind",
        "observed_date",
        "controller",
        "manifest",
        "acquisition_policy_sha256",
        "summary",
        "protected_state",
        "cases",
        "limitations",
    }
    assert baseline["schema_version"] == "1.0.0"
    assert baseline["kind"] == "object_source_preparation_baseline"
    assert baseline["manifest"] == {
        "benchmark_version": "0.1.0",
        "sha256": _sha256(ROOT / "benchmarks" / "v0.1" / "manifest.json"),
    }
    assert baseline["acquisition_policy_sha256"] == OBJECT_SOURCE_POLICY_SHA256
    assert GIT_OID.fullmatch(baseline["controller"]["git_sha"])
    assert summary["case_count"] == summary["accepted_count"] == 20
    assert summary["rejected_count"] == 0
    assert summary["independently_reverified_count"] == 20
    assert summary["receipt_index_built"] is False
    assert summary["model_call_count"] == summary["authorized_spend_microusd"] == 0
    assert summary["campaign_readiness_changed"] is False
    assert summary["benchmark_result_rows_appended"] == 0
    assert summary["benchmark_events_appended"] == 0
    assert [case["case_id"] for case in cases] == [f"rk-v0.1-{index:03d}" for index in range(1, 21)]
    assert all(case["status"] == "accepted_and_reverified" for case in cases)
    assert summary["repair_path_count"] == sum(case["repair_count"] for case in cases)
    assert summary["fallback_blob_fetch_count"] == sum(
        case["fallback_blob_count"] for case in cases
    )
    assert summary["tracked_symlink_count"] == sum(case["symlink_count"] for case in cases)
    assert summary["gitlink_count"] == sum(case["gitlink_count"] for case in cases)
    for case in cases:
        assert SHA256.fullmatch(case["receipt_sha256"])
        assert SHA256.fullmatch(case["archive_sha256"])
        assert SHA256.fullmatch(case["content_tree_sha256"])
        assert SHA256.fullmatch(case["object_manifest_sha256"])
        assert GIT_OID.fullmatch(case["git_tree_oid"])
        assert case["repair_count"] == len(case["repairs"])
        assert 0 <= case["fallback_blob_count"] <= case["repair_count"] <= 64
        assert 0 < case["prepare_duration_seconds"] < 600
        assert 0 < case["reverify_duration_seconds"] < 600
        assert all(set(repair) == {"path", "reason"} for repair in case["repairs"])
        assert all(
            repair["reason"] in {"missing", "blob_oid_mismatch"} for repair in case["repairs"]
        )
        assert "/Users/" not in json.dumps(case)


def test_object_source_baseline_timings_and_protected_hashes_are_consistent() -> None:
    baseline = _strict_json(BASELINE)
    summary = baseline["summary"]
    cases = baseline["cases"]
    for field, case_field in (
        ("prepare_duration_seconds", "prepare_duration_seconds"),
        ("reverify_duration_seconds", "reverify_duration_seconds"),
    ):
        values = [case[case_field] for case in cases]
        recorded = summary[field]
        assert recorded == {
            "total": round(sum(values), 3),
            "median": round(statistics.median(values), 3),
            "minimum": min(values),
            "maximum": max(values),
        }

    protected = baseline["protected_state"]
    expected = {
        "campaign_sha256_before_and_after": "campaign.json",
        "results_sha256_before_and_after": "results.jsonl",
        "smoke_ledger_sha256_before_and_after": "ledger/smoke-events.jsonl",
        "scored_ledger_sha256_before_and_after": "ledger/scored-events.jsonl",
        "summary_sha256_before_and_after": "summary.json",
    }
    benchmark_root = ROOT / "benchmarks" / "v0.1"
    assert set(protected) == set(expected)
    for field, relative_path in expected.items():
        assert protected[field] == _sha256(benchmark_root / relative_path)
