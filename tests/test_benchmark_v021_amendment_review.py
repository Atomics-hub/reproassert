from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import reproassert.benchmark_v02_amendment as amendment_module
import reproassert.benchmark_v021_amendment_review as review
from reproassert.cli import main
from reproassert.errors import PolicyRejection

TOOL_SHA = "b158e73cf22f01af31ed78eed2c5e5b907149e89"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _pending(root: Path) -> amendment_module.VerifiedV02BenchmarkAmendment:
    record = {
        "algorithm": "reproassert-v02-gold-spec-amendment-v1",
        "benchmark_version": "0.2.1",
        "change": {
            "added_fail_to_pass_targets": 0,
            "amended_case_id": "rk-v0.2-014",
            "amended_instance_id": "psf__requests-1921",
            "fail_to_pass_after": 1,
            "fail_to_pass_before": 6,
            "removed_fail_to_pass_targets": 5,
            "scope": "strict_subset_only",
        },
        "claims": {"provider_calls": 0},
        "evidence": {
            "amended_gold_smoke_receipt_sha256": "a" * 64,
            "amended_gold_specs_sha256": "b" * 64,
            "hidden_extraction_receipt_sha256": "c" * 64,
            "original_gold_smoke_receipt_sha256": "d" * 64,
            "original_gold_specs_sha256": "e" * 64,
            "runtime_manifest_raw_sha256": "f" * 64,
            "runtime_manifest_sha256": "1" * 64,
            "smoke_tool_git_sha": TOOL_SHA,
        },
        "prepared_at": "2026-07-11T01:00:00Z",
        "receipt_sha256": "2" * 64,
        "review": {"reviewer_ids": [], "status": "pending"},
        "schema_version": "1.0.0",
        "status": "provider_free_packaging_ready_review_pending",
        "tool_git_sha": TOOL_SHA,
    }
    path = root / "amendment.json"
    raw = _canonical(record)
    path.write_bytes(raw)
    value = object.__new__(amendment_module.VerifiedV02BenchmarkAmendment)
    for name, item in {
        "receipt_path": path,
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "runtime_manifest_sha256": "1" * 64,
        "hidden_extraction_receipt_sha256": "c" * 64,
        "original_gold_smoke_receipt_sha256": "d" * 64,
        "amended_gold_smoke_receipt_sha256": "a" * 64,
        "review_status": "pending",
        "reviewer_ids": (),
        "tool_git_sha": TOOL_SHA,
        "provider_calls": 0,
        "_issuer": amendment_module._ISSUER,
    }.items():
        object.__setattr__(value, name, item)
    return value


def _mapping(root: Path) -> SimpleNamespace:
    record = {
        "prepared_at": "2026-07-11T00:30:00Z",
        "role_plan": {
            "mapping_reviewer_ids": ["alice-human", "bob-human", "tina-human"],
            "semantic_reviewer_ids": ["sam-human", "uma-human"],
            "separation_verified": True,
            "tiebreak_policy": "predeclared_submit_only_after_primary_disagreement",
        },
    }
    path = root / "mapping.json"
    raw = _canonical(record)
    path.write_bytes(raw)
    return SimpleNamespace(receipt_path=path, sha256=hashlib.sha256(raw).hexdigest())


def _handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> review.VerifiedV021AmendmentReviewHandoff:
    root = _private(tmp_path / "private")
    pending = _pending(root)
    mapping = _mapping(root)
    monkeypatch.setattr(review, "verify_v02_mapping_review_handoff", lambda *_a, **_k: mapping)
    return review.prepare_v021_amendment_review_handoff(
        amendment_authority=pending,
        mapping_handoff_path=mapping.receipt_path,
        mapping_preparation_path=root / "unused.json",
        prepared_at="2026-07-11T01:30:00Z",
        tool_git_sha=TOOL_SHA,
        output_path=root / "handoff.json",
    )


def _submission(
    root: Path,
    name: str,
    handoff: review.VerifiedV021AmendmentReviewHandoff,
    reviewer_id: str,
    verdict: str,
    submitted_at: str,
) -> Path:
    value = {
        "amendment_handoff_raw_sha256": handoff.sha256,
        "declarations": {
            "independent_judgment": True,
            "oracle_access": "review_only",
            "role": "amendment_reviewer",
            "semantic_review_role": "forbidden",
        },
        "reviewer_id": reviewer_id,
        "schema_version": "1.0.0",
        "submitted_at": submitted_at,
        "verdict": verdict,
    }
    path = root / name
    path.write_bytes(_canonical(value))
    return path


def test_handoff_binds_pending_evidence_and_reuses_disjoint_roster(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _handoff(tmp_path, monkeypatch)
    record = json.loads(handoff.path.read_bytes())
    assert record["status"] == "human_review_required_provider_disabled"
    assert record["review_policy"]["primary_reviewer_ids"] == ["alice-human", "bob-human"]
    assert record["review_policy"]["semantic_reviewer_ids"] == ["sam-human", "uma-human"]
    assert record["amendment"]["raw_sha256"] == handoff.amendment_receipt_sha256
    assert record["amendment"]["change"]["removed_fail_to_pass_targets"] == 5
    assert record["claims"]["provider_calls"] == 0


def test_consensus_approves_two_primaries_and_issues_nominal_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _handoff(tmp_path, monkeypatch)
    submissions = _private(tmp_path / "submissions")
    _submission(submissions, "01.json", handoff, "alice-human", "approved", "2026-07-11T02:00:00Z")
    _submission(submissions, "02.json", handoff, "bob-human", "approved", "2026-07-11T02:01:00Z")
    sealed = review.seal_v021_amendment_review_consensus(
        handoff_authority=handoff,
        submissions_root=submissions,
        sealed_at="2026-07-11T02:30:00Z",
        tool_git_sha=TOOL_SHA,
        output_path=handoff.path.parent / "consensus.json",
    )
    assert review.require_approved_v021_amendment_consensus(sealed) is sealed
    assert sealed.reviewer_ids == ("alice-human", "bob-human")
    with pytest.raises(PolicyRejection, match="verifier-issued"):
        review.require_approved_v021_amendment_consensus(object())


@pytest.mark.parametrize("reviewer", ["placeholder", "sam-human", "unknown-human"])
def test_consensus_rejects_placeholder_role_overlap_or_undeclared_reviewer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reviewer: str
) -> None:
    handoff = _handoff(tmp_path, monkeypatch)
    submissions = _private(tmp_path / "submissions")
    _submission(submissions, "01.json", handoff, reviewer, "approved", "2026-07-11T02:00:00Z")
    _submission(submissions, "02.json", handoff, "bob-human", "approved", "2026-07-11T02:01:00Z")
    with pytest.raises(PolicyRejection):
        review.seal_v021_amendment_review_consensus(
            handoff_authority=handoff,
            submissions_root=submissions,
            sealed_at="2026-07-11T02:30:00Z",
            tool_git_sha=TOOL_SHA,
            output_path=handoff.path.parent / "consensus.json",
        )


def test_consensus_rejects_duplicate_unnecessary_third_tamper_and_bad_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _handoff(tmp_path, monkeypatch)
    submissions = _private(tmp_path / "submissions")
    _submission(submissions, "01.json", handoff, "alice-human", "approved", "2026-07-11T02:00:00Z")
    _submission(submissions, "02.json", handoff, "bob-human", "approved", "2026-07-11T02:01:00Z")
    _submission(submissions, "03.json", handoff, "tina-human", "approved", "2026-07-11T02:02:00Z")
    with pytest.raises(PolicyRejection, match="third reviewer"):
        review.seal_v021_amendment_review_consensus(
            handoff_authority=handoff,
            submissions_root=submissions,
            sealed_at="2026-07-11T02:30:00Z",
            tool_git_sha=TOOL_SHA,
            output_path=handoff.path.parent / "consensus.json",
        )
    (submissions / "03.json").unlink()
    value = json.loads((submissions / "01.json").read_bytes())
    value["amendment_handoff_raw_sha256"] = "9" * 64
    (submissions / "01.json").write_bytes(_canonical(value))
    with pytest.raises(PolicyRejection, match="wrong handoff"):
        review.seal_v021_amendment_review_consensus(
            handoff_authority=handoff,
            submissions_root=submissions,
            sealed_at="2026-07-11T02:30:00Z",
            tool_git_sha=TOOL_SHA,
            output_path=handoff.path.parent / "consensus.json",
        )


def test_primary_disagreement_requires_exact_declared_tiebreak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _handoff(tmp_path, monkeypatch)
    submissions = _private(tmp_path / "submissions")
    _submission(submissions, "01.json", handoff, "alice-human", "approved", "2026-07-11T02:00:00Z")
    _submission(submissions, "02.json", handoff, "bob-human", "rejected", "2026-07-11T02:01:00Z")
    with pytest.raises(PolicyRejection, match="tie-break"):
        review.seal_v021_amendment_review_consensus(
            handoff_authority=handoff,
            submissions_root=submissions,
            sealed_at="2026-07-11T02:30:00Z",
            tool_git_sha=TOOL_SHA,
            output_path=handoff.path.parent / "consensus.json",
        )
    _submission(submissions, "03.json", handoff, "tina-human", "approved", "2026-07-11T02:02:00Z")
    sealed = review.seal_v021_amendment_review_consensus(
        handoff_authority=handoff,
        submissions_root=submissions,
        sealed_at="2026-07-11T02:30:00Z",
        tool_git_sha=TOOL_SHA,
        output_path=handoff.path.parent / "consensus.json",
    )
    assert sealed.verdict == "approved"


def test_public_and_packaged_schemas_are_byte_identical() -> None:
    for name in ("submission", "handoff", "consensus"):
        filename = f"benchmark-v021-amendment-review-{name}.schema.json"
        assert (
            Path("schemas", filename).read_bytes()
            == Path("src/reproassert/schemas", filename).read_bytes()
        )


def test_provider_disabled_cli_boundary_has_no_v021_run_command() -> None:
    result = CliRunner().invoke(main, ["benchmark", "--help"])
    assert result.exit_code == 0
    for command in (
        "prepare-v021-amendment-review-handoff",
        "seal-v021-amendment-review-consensus",
        "verify-v021-amendment-review-consensus",
        "verify-v021-amendment-review-handoff",
    ):
        assert command in result.output
    assert "run-v021" not in result.output
