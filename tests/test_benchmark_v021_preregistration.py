from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

import reproassert.benchmark_v02_amendment as amendment_module
import reproassert.benchmark_v021_amendment_review as review_module
import reproassert.benchmark_v021_preregistration as subject
from reproassert.cli import main
from reproassert.errors import PolicyRejection

TOOL_SHA = "9" * 40
FROZEN = "2026-07-11T10:00:00Z"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )


def _write(path: Path, value: object) -> Path:
    path.write_bytes(_canonical(value))
    return path


def _authorities(root: Path, *, approved: bool = True) -> tuple[object, object]:
    amendment_path = _write(
        root / "amendment.json",
        {"prepared_at": "2026-07-11T01:00:00Z", "receipt_sha256": "a" * 64},
    )
    amendment_raw_sha = hashlib.sha256(amendment_path.read_bytes()).hexdigest()
    amendment = object.__new__(amendment_module.VerifiedV02BenchmarkAmendment)
    for name, value in {
        "receipt_path": amendment_path,
        "receipt_sha256": amendment_raw_sha,
        "tool_git_sha": TOOL_SHA,
        "provider_calls": 0,
        "_issuer": amendment_module._ISSUER,
    }.items():
        object.__setattr__(amendment, name, value)
    consensus_path = _write(
        root / "amendment-consensus.json",
        {
            "seal_sha256": "b" * 64,
            "sealed_at": "2026-07-11T03:00:00Z",
            "verdict": "approved" if approved else "rejected",
        },
    )
    consensus = object.__new__(review_module.VerifiedV021AmendmentConsensus)
    for name, value in {
        "path": consensus_path,
        "sha256": hashlib.sha256(consensus_path.read_bytes()).hexdigest(),
        "amendment_receipt_sha256": amendment_raw_sha,
        "reviewer_ids": ("alice-human", "bob-human"),
        "verdict": "approved" if approved else "rejected",
        "tool_git_sha": TOOL_SHA,
        "provider_calls": 0,
        "_issuer": review_module._ISSUER,
    }.items():
        object.__setattr__(consensus, name, value)
    return amendment, consensus


def _fixtures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, ready: int = 20
) -> dict[str, object]:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    cases_root = root / "cases"
    cases_root.mkdir(mode=0o700)
    packages: list[dict[str, object]] = []
    for number in range(1, 21):
        path = _write(
            cases_root / f"package-{number:03d}.json",
            {
                "blockers": ["exact_image_amendment_review_pending", "spend_not_authorized"],
                "case_id": f"rk-v0.2-{number:03d}",
                "dependency": {"status": "amendment_review_pending"},
            },
        )
        packages.append(
            {"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        )
    cases_path = _write(
        cases_root / "cases.json",
        {
            "benchmark_version": "0.2.1",
            "dependency_ready_count": 0,
            "packages": packages,
            "preparation_set_sha256": "c" * 64,
            "prepared_at": "2026-07-11T04:00:00Z",
            "request_set_sha256": "d" * 64,
            "tool": {"git_sha": TOOL_SHA},
        },
    )
    capability_path = _write(
        root / "capability.json",
        {
            "algorithm": "reproassert-v02-exact-image-capability-index-v2",
            "benchmark_version": "0.2.1",
            "index_sha256": "e" * 64,
            "prepared_at": "2026-07-11T05:00:00Z",
            "tool_git_sha": TOOL_SHA,
        },
    )
    mapping_path = _write(
        root / "mapping.json",
        {
            "cases": [
                {
                    "case_id": f"rk-v0.2-{number:03d}",
                    "consensus": {"selected_hunk_ids": [f"h{number}"], "verdict": "approved"},
                }
                for number in range(1, 21)
            ],
            "mapping_preparation_receipt_sha256": "6" * 64,
            "sealed_at": "2026-07-11T06:00:00Z",
            "seal_sha256": "f" * 64,
        },
    )
    chronology_path = _write(
        root / "chronology.json",
        {"captured_at": "2026-07-11T02:00:00Z", "receipt_sha256": "3" * 64},
    )
    cohort_path = _write(root / "cohort.json", {"cohort_plan_sha256": "1" * 64})
    hidden_path = _write(root / "hidden.json", {"receipt_sha256": "4" * 64, "status": "verified"})
    gold_path = _write(
        root / "gold.json",
        {"counts": {"semantic_valid": ready}, "receipt_sha256": "5" * 64},
    )
    runtime_path = _write(root / "runtime.json", {"cases": 20})
    mapping_prep = _write(root / "mapping-prep.json", {"cases": 20})
    pricing_path = root / "pricing.json"
    pricing_path.write_bytes(
        Path("benchmarks/v0.2-draft/gpt-5.4-mini-pricing-snapshot.json").read_bytes()
    )
    issue_root = root / "issues"
    issue_root.mkdir(mode=0o700)
    cases_record = json.loads(cases_path.read_bytes())
    cases_record["inputs"] = {
        "cohort_plan": {"sha256": hashlib.sha256(cohort_path.read_bytes()).hexdigest()},
        "hidden_extraction": {"sha256": hashlib.sha256(hidden_path.read_bytes()).hexdigest()},
        "pricing_snapshot": {"sha256": hashlib.sha256(pricing_path.read_bytes()).hexdigest()},
    }
    _write(cases_path, cases_record)
    _write(
        mapping_prep,
        {
            "cases": 20,
            "hidden_extraction_receipt_sha256": json.loads(hidden_path.read_bytes())[
                "receipt_sha256"
            ],
            "receipt_sha256": "6" * 64,
        },
    )
    capability_record = json.loads(capability_path.read_bytes())
    capability_record["cases"] = [
        {
            "case_id": f"rk-v0.2-{number:03d}",
            "evidence": {
                "gold_smoke": {"receipt_sha256": hashlib.sha256(gold_path.read_bytes()).hexdigest()}
            },
        }
        for number in range(1, 21)
    ]
    _write(capability_path, capability_record)
    amendment, consensus = _authorities(root)
    object.__setattr__(
        amendment,
        "amended_gold_smoke_receipt_sha256",
        hashlib.sha256(gold_path.read_bytes()).hexdigest(),
    )

    monkeypatch.setattr(
        subject,
        "verify_v02_cases",
        lambda _path: SimpleNamespace(
            root=cases_root,
            receipt_path=cases_path,
            receipt_sha256=hashlib.sha256(cases_path.read_bytes()).hexdigest(),
            case_count=20,
            dependency_ready_count=0,
            provider_calls=0,
        ),
    )
    monkeypatch.setattr(
        subject,
        "verify_v02_chronology_evidence",
        lambda *_a, **_k: SimpleNamespace(
            path=chronology_path,
            sha256=hashlib.sha256(chronology_path.read_bytes()).hexdigest(),
            case_count=20,
            issue_precedes_fix_count=20,
            provider_calls=0,
        ),
    )
    monkeypatch.setattr(
        subject,
        "verify_v02_mapping_consensus",
        lambda *_a, **_k: SimpleNamespace(
            path=mapping_path,
            sha256=hashlib.sha256(mapping_path.read_bytes()).hexdigest(),
            case_count=20,
        ),
    )
    monkeypatch.setattr(
        subject,
        "verify_v02_mapping_packets",
        lambda _path: SimpleNamespace(
            root=root,
            receipt_path=mapping_prep,
            receipt_sha256=hashlib.sha256(mapping_prep.read_bytes()).hexdigest(),
            case_count=20,
        ),
    )
    monkeypatch.setattr(
        subject,
        "verify_v02_exact_image_capability_index",
        lambda *_a, **_k: SimpleNamespace(
            path=capability_path,
            sha256=hashlib.sha256(capability_path.read_bytes()).hexdigest(),
            case_count=20,
            runtime_attested_count=20,
            evaluator_preflight_ready_count=ready,
            infrastructure_failure_count=20 - ready,
            provider_calls=0,
        ),
    )
    monkeypatch.setattr(
        subject,
        "load_v02_leak_audited_cohort_plan",
        lambda _path: {"cohort_plan_sha256": "1" * 64},
    )
    return {
        "amendment_authority": amendment,
        "amendment_consensus_authority": consensus,
        "cases_preparation_path": cases_path,
        "cohort_plan_path": cohort_path,
        "chronology_path": chronology_path,
        "hidden_extraction_receipt": hidden_path,
        "issue_responses_root": issue_root,
        "mapping_preparation_path": mapping_prep,
        "mapping_consensus_path": mapping_path,
        "capability_index_path": capability_path,
        "runtime_manifest_path": runtime_path,
        "expected_runtime_manifest_sha256": "2" * 64,
        "gold_smoke_receipt_path": gold_path,
        "pricing_snapshot_path": pricing_path,
        "frozen_at": FROZEN,
        "tool_git_sha": TOOL_SHA,
        "output_path": root / "preregistration.json",
    }


def test_approved_consensus_upgrades_pending_packages_to_disabled_20_of_20(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    verified = subject.prepare_v021_preregistration(**values)  # type: ignore[arg-type]
    record = json.loads(verified.path.read_bytes())
    schema = json.loads(Path("schemas/benchmark-v021-preregistration.schema.json").read_text())
    Draft202012Validator(schema).validate(record)
    assert verified.dependency_ready_count == 20
    assert verified.execution_enabled is False
    assert record["claims"]["dependency_ready_count_before_consensus"] == 0
    assert record["claims"]["dependency_ready_count_after_consensus"] == 20
    assert record["status"] == "execution_disabled_until_v021_runtime_migration"
    assert record["policy"]["total_cap_usd"] == "5.00"
    assert record["policy"]["case_cap_usd"] == "0.25"
    assert record["approval"]["authorized"] is False
    assert verified.lineage_commitment_sha256 in verified.approval_statement
    serialized = json.dumps(record).lower()
    assert "api_key" not in serialized
    assert "secret" not in serialized
    assert record["policy"]["credential_fields_allowed"] is False


def test_rejects_legacy_19_of_20(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = _fixtures(tmp_path, monkeypatch, ready=19)
    with pytest.raises(PolicyRejection, match="19/1"):
        subject.prepare_v021_preregistration(**values)  # type: ignore[arg-type]


def test_rejects_nonapproved_or_structural_consensus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    with pytest.raises(PolicyRejection, match="verifier-issued"):
        subject.prepare_v021_preregistration(
            **{**values, "amendment_consensus_authority": object()}  # type: ignore[arg-type]
        )
    rejected_amendment, rejected = _authorities(tmp_path / "private", approved=False)
    with pytest.raises(PolicyRejection, match="not approved"):
        subject.prepare_v021_preregistration(
            **{
                **values,
                "amendment_authority": rejected_amendment,
                "amendment_consensus_authority": rejected,
            }  # type: ignore[arg-type]
        )


def test_tampering_and_case_approval_bypass_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    verified = subject.prepare_v021_preregistration(**values)  # type: ignore[arg-type]
    record = json.loads(verified.path.read_bytes())
    record["policy"]["execution_enabled"] = True
    verified.path.write_bytes(_canonical(record))
    with pytest.raises(PolicyRejection, match="identity"):
        subject.verify_v021_preregistration(
            verified.path,
            **{
                key: value
                for key, value in values.items()
                if key not in {"frozen_at", "tool_git_sha", "output_path"}
            },  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("input_name", ["cohort_plan", "hidden_extraction", "pricing_snapshot"])
def test_rejects_mixed_case_input_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, input_name: str
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    cases_path = Path(values["cases_preparation_path"])
    record = json.loads(cases_path.read_bytes())
    record["inputs"][input_name]["sha256"] = "0" * 64
    _write(cases_path, record)
    with pytest.raises(PolicyRejection, match="different campaign lineages"):
        subject.prepare_v021_preregistration(**values)  # type: ignore[arg-type]


def test_rejects_mixed_mapping_hidden_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    mapping_path = Path(values["mapping_preparation_path"])
    record = json.loads(mapping_path.read_bytes())
    record["hidden_extraction_receipt_sha256"] = "0" * 64
    _write(mapping_path, record)
    with pytest.raises(PolicyRejection, match="different campaign lineages"):
        subject.prepare_v021_preregistration(**values)  # type: ignore[arg-type]


def test_rejects_authority_reread_digest_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    verified_cases = subject.verify_v02_cases

    def mismatched_cases(path: Path) -> SimpleNamespace:
        authority = verified_cases(path)
        authority.receipt_sha256 = "0" * 64
        return authority

    monkeypatch.setattr(subject, "verify_v02_cases", mismatched_cases)
    with pytest.raises(PolicyRejection, match="changed after verification"):
        subject.prepare_v021_preregistration(**values)  # type: ignore[arg-type]


def test_rejects_mapping_preparation_swap_after_consensus_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    verified_mapping = subject.verify_v02_mapping_consensus

    def swap_after_verification(*args: object, **kwargs: object) -> SimpleNamespace:
        authority = verified_mapping(*args, **kwargs)
        path = Path(values["mapping_preparation_path"])
        record = json.loads(path.read_bytes())
        record["receipt_sha256"] = "0" * 64
        _write(path, record)
        return authority

    monkeypatch.setattr(subject, "verify_v02_mapping_consensus", swap_after_verification)
    with pytest.raises(PolicyRejection, match="changed after verification"):
        subject.prepare_v021_preregistration(**values)  # type: ignore[arg-type]


def test_rejects_gold_swap_after_capability_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    verified_capability = subject.verify_v02_exact_image_capability_index

    def swap_after_verification(*args: object, **kwargs: object) -> SimpleNamespace:
        authority = verified_capability(*args, **kwargs)
        _write(
            Path(values["gold_smoke_receipt_path"]),
            {"counts": {"semantic_valid": 0}, "receipt_sha256": "0" * 64},
        )
        return authority

    monkeypatch.setattr(subject, "verify_v02_exact_image_capability_index", swap_after_verification)
    with pytest.raises(PolicyRejection, match="changed after amendment verification"):
        subject.prepare_v021_preregistration(**values)  # type: ignore[arg-type]


def test_schema_is_bundled_and_cli_has_no_v021_run_path() -> None:
    public = Path("schemas/benchmark-v021-preregistration.schema.json")
    bundled = Path("src/reproassert/schemas/benchmark-v021-preregistration.schema.json")
    assert public.read_bytes() == bundled.read_bytes()
    Draft202012Validator.check_schema(json.loads(public.read_text()))
    result = CliRunner().invoke(main, ["benchmark", "--help"])
    assert result.exit_code == 0
    assert "prepare-v021-preregistration" in result.output
    assert "verify-v021-preregistration" in result.output
    assert "run-v021" not in result.output
