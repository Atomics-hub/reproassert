from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

import reproassert.benchmark_v02_amendment as amendment_module
import reproassert.benchmark_v021_automated_evidence as evidence_module
import reproassert.benchmark_v021_automated_preregistration as prereg_module
from reproassert.errors import PolicyRejection

TOOL_SHA = "9" * 40
VERIFIED_AT = "2026-07-11T10:00:00Z"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
    )


def _write(path: Path, value: object) -> Path:
    path.write_bytes(_canonical(value))
    return path


def _fixtures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    cases_root = root / "cases"
    cases_root.mkdir(mode=0o700)
    mapping_root = root / "mapping"
    mapping_root.mkdir(mode=0o700)
    hidden = _write(root / "hidden.json", {"receipt_sha256": "1" * 64})
    gold = _write(root / "gold.json", {"receipt_sha256": "2" * 64})
    cohort = _write(root / "cohort.json", {"placeholder": True})
    runtime = _write(root / "runtime.json", {"cases": 20})
    pricing = root / "pricing.json"
    pricing.write_bytes(
        Path("benchmarks/v0.2-draft/gpt-5.4-mini-pricing-snapshot.json").read_bytes()
    )

    packages: list[dict[str, object]] = []
    for number in range(1, 21):
        package = _write(
            cases_root / f"package-{number:03d}.json",
            {
                "blockers": ["exact_image_amendment_review_pending", "spend_not_authorized"],
                "case_id": f"rk-v0.2-{number:03d}",
                "dependency": {"status": "amendment_review_pending"},
            },
        )
        packages.append(
            {"path": package.name, "sha256": hashlib.sha256(package.read_bytes()).hexdigest()}
        )
    cases_path = _write(
        cases_root / "cases.json",
        {
            "benchmark_version": "0.2.1",
            "dependency_ready_count": 0,
            "inputs": {
                "cohort_plan": {"sha256": hashlib.sha256(cohort.read_bytes()).hexdigest()},
                "hidden_extraction": {"sha256": hashlib.sha256(hidden.read_bytes()).hexdigest()},
                "pricing_snapshot": {"sha256": hashlib.sha256(pricing.read_bytes()).hexdigest()},
            },
            "packages": packages,
            "preparation_set_sha256": "3" * 64,
            "prepared_at": "2026-07-11T06:00:00Z",
            "request_set_sha256": "4" * 64,
            "tool": {"git_sha": TOOL_SHA},
        },
    )

    patch_sha_by_case: dict[str, str] = {}
    mapping_rows: list[dict[str, object]] = []
    for number in range(1, 21):
        case_id = f"rk-v0.2-{number:03d}"
        patch_sha = hashlib.sha256(f"fix-{case_id}".encode()).hexdigest()
        patch_sha_by_case[case_id] = patch_sha
        packet = _write(
            mapping_root / f"packet-{number:03d}.json",
            {
                "case_id": case_id,
                "hunk_inventory": [{"atomic_id": f"{case_id}:h001:abc"}],
                "patch_algebra": {
                    "ordered_atomic_ids": [f"{case_id}:h001:abc"],
                    "ordered_hunk_sha256": ["5" * 64],
                },
                "production_patch": {"bytes": 10, "sha256": patch_sha},
                "reviews": [],
                "status": "awaiting_two_independent_mapping_reviews",
            },
        )
        mapping_rows.append(
            {
                "case_id": case_id,
                "hunk_count": 1,
                "packet": {
                    "path": packet.name,
                    "sha256": hashlib.sha256(packet.read_bytes()).hexdigest(),
                },
                "production_patch_sha256": patch_sha,
                "status": "review_required",
            }
        )
    mapping_path = _write(
        mapping_root / "mapping.json",
        {
            "cases": mapping_rows,
            "hidden_extraction_receipt_sha256": "1" * 64,
            "prepared_at": "2026-07-11T07:00:00Z",
            "receipt_sha256": "6" * 64,
            "tool": {"git_sha": TOOL_SHA},
        },
    )
    chronology = _write(
        root / "chronology.json",
        {
            "captured_at": "2026-07-11T05:00:00Z",
            "receipt_sha256": "7" * 64,
            "tool_git_sha": TOOL_SHA,
        },
    )
    amendment_path = _write(
        root / "amendment.json",
        {
            "prepared_at": "2026-07-11T04:00:00Z",
            "receipt_sha256": "8" * 64,
            "tool_git_sha": TOOL_SHA,
        },
    )
    amendment = object.__new__(amendment_module.VerifiedV02BenchmarkAmendment)
    for name, value in {
        "receipt_path": amendment_path,
        "receipt_sha256": hashlib.sha256(amendment_path.read_bytes()).hexdigest(),
        "amended_gold_smoke_receipt_sha256": hashlib.sha256(gold.read_bytes()).hexdigest(),
        "review_status": "pending",
        "reviewer_ids": (),
        "tool_git_sha": TOOL_SHA,
        "provider_calls": 0,
        "_issuer": amendment_module._ISSUER,
    }.items():
        object.__setattr__(amendment, name, value)
    capability_path = _write(
        root / "capability.json",
        {
            "algorithm": "reproassert-v02-exact-image-capability-index-v2",
            "benchmark_version": "0.2.1",
            "cases": [
                {
                    "case_id": case_id,
                    "evidence": {
                        "benchmark_amendment_receipt_sha256": amendment.receipt_sha256,
                        "case_id": case_id,
                        "gold_smoke": {
                            "case_classification": "semantic_valid",
                            "case_reason": "fails_on_base_passes_on_fixed",
                            "receipt_sha256": hashlib.sha256(gold.read_bytes()).hexdigest(),
                        },
                        "hidden_inputs": {
                            "production_patch_bytes": 10,
                            "production_patch_sha256": patch_sha_by_case[case_id],
                        },
                    },
                    "status": "runtime_attested_evaluator_preflight_ready",
                }
                for case_id in patch_sha_by_case
            ],
            "index_sha256": "a" * 64,
            "prepared_at": "2026-07-11T08:00:00Z",
            "tool_git_sha": TOOL_SHA,
        },
    )
    issue_root = root / "issues"
    issue_root.mkdir(mode=0o700)
    plan = {
        "cases": [
            {
                "case_id": f"rk-v0.2-{number:03d}",
                "oracle_leak_audit": {
                    "direct_own_fixing_pr_reference": False,
                    "oracle_leak_free": True,
                    "production_added_line_overlap": False,
                    "test_added_line_overlap": False,
                },
            }
            for number in range(1, 21)
        ]
    }

    monkeypatch.setattr(
        evidence_module,
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
        evidence_module,
        "verify_v02_chronology_evidence",
        lambda *_args, **_kwargs: SimpleNamespace(
            path=chronology,
            sha256=hashlib.sha256(chronology.read_bytes()).hexdigest(),
            case_count=20,
            issue_precedes_fix_count=20,
            provider_calls=0,
        ),
    )
    monkeypatch.setattr(
        evidence_module,
        "verify_v02_mapping_packets",
        lambda _path: SimpleNamespace(
            root=mapping_root,
            receipt_path=mapping_path,
            receipt_sha256=hashlib.sha256(mapping_path.read_bytes()).hexdigest(),
            case_count=20,
        ),
    )
    monkeypatch.setattr(
        evidence_module,
        "verify_v02_exact_image_capability_index",
        lambda *_args, **_kwargs: SimpleNamespace(
            path=capability_path,
            sha256=hashlib.sha256(capability_path.read_bytes()).hexdigest(),
            case_count=20,
            runtime_attested_count=20,
            evaluator_preflight_ready_count=20,
            infrastructure_failure_count=0,
            provider_calls=0,
        ),
    )
    monkeypatch.setattr(evidence_module, "load_v02_leak_audited_cohort_plan", lambda _path: plan)
    return {
        "amendment_authority": amendment,
        "cases_preparation_path": cases_path,
        "cohort_plan_path": cohort,
        "chronology_path": chronology,
        "hidden_extraction_receipt": hidden,
        "issue_responses_root": issue_root,
        "mapping_preparation_path": mapping_path,
        "capability_index_path": capability_path,
        "runtime_manifest_path": runtime,
        "expected_runtime_manifest_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
        "gold_smoke_receipt_path": gold,
        "pricing_snapshot_path": pricing,
        "verified_at": VERIFIED_AT,
        "tool_git_sha": TOOL_SHA,
        "output_path": root / "automated-evidence.json",
        "_plan": plan,
        "_mapping_root": mapping_root,
    }


def _prepare(values: dict[str, object]) -> evidence_module.VerifiedV021AutomatedEvidence:
    return evidence_module.prepare_v021_automated_evidence(
        **{key: value for key, value in values.items() if not key.startswith("_")}  # type: ignore[arg-type]
    )


def test_automated_evidence_and_preregistration_are_honest_and_schema_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    evidence = _prepare(values)
    evidence_record = json.loads(evidence.path.read_bytes())
    evidence_schema = json.loads(
        Path("schemas/benchmark-v021-automated-evidence.schema.json").read_text()
    )
    Draft202012Validator(evidence_schema).validate(evidence_record)
    prereg = prereg_module.prepare_v021_automated_preregistration(
        automated_evidence_authority=evidence,
        frozen_at="2026-07-11T11:00:00Z",
        output_path=evidence.path.parent / "automated-preregistration.json",
    )
    prereg_record = json.loads(prereg.path.read_bytes())
    prereg_schema = json.loads(
        Path("schemas/benchmark-v021-automated-preregistration.schema.json").read_text()
    )
    Draft202012Validator(prereg_schema).validate(prereg_record)
    assert evidence_record["claims"]["automated_oracle_validated"] is True
    assert evidence_record["claims"]["human_reviewed"] is False
    assert evidence_record["claims"]["maintainer_validated"] is False
    assert evidence_record["claims"]["provider_calls"] == 0
    assert prereg.dependency_ready_count == 20
    assert prereg.execution_enabled is False
    assert prereg.lineage_commitment_sha256 in prereg.approval_statement
    assert "reviewer_ids" not in json.dumps(evidence_record)


def test_public_fields_cannot_self_mint_authority() -> None:
    with pytest.raises(TypeError, match="verifier-issued"):
        evidence_module.VerifiedV021AutomatedEvidence(path=Path("x"), sha256="0" * 64)
    with pytest.raises(PolicyRejection, match="verifier-issued"):
        evidence_module.require_v021_automated_evidence(SimpleNamespace(provider_calls=0))
    with pytest.raises(TypeError, match="verifier-issued"):
        prereg_module.VerifiedV021AutomatedPreregistration(path=Path("x"), sha256="0" * 64)


def test_rejects_mixed_hidden_mapping_and_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    capability = Path(values["capability_index_path"])
    record = json.loads(capability.read_bytes())
    record["cases"][0]["evidence"]["hidden_inputs"]["production_patch_sha256"] = "0" * 64
    _write(capability, record)
    with pytest.raises(PolicyRejection, match="mixed or invalid"):
        _prepare(values)


def test_rejects_case014_waiver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    package = Path(values["cases_preparation_path"]).parent / "package-014.json"
    record = json.loads(package.read_bytes())
    record["dependency"]["status"] = "network_waiver_ready"
    _write(package, record)
    cases = Path(values["cases_preparation_path"])
    cases_record = json.loads(cases.read_bytes())
    cases_record["packages"][13]["sha256"] = hashlib.sha256(package.read_bytes()).hexdigest()
    _write(cases, cases_record)
    with pytest.raises(PolicyRejection, match="uniform pending"):
        _prepare(values)


def test_rejects_gold_leak(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    plan = values["_plan"]
    assert isinstance(plan, dict)
    plan["cases"][0]["oracle_leak_audit"]["production_added_line_overlap"] = True  # type: ignore[index]
    with pytest.raises(PolicyRejection, match="gold-oracle leak"):
        _prepare(values)


@pytest.mark.parametrize("mutation", ["chronology", "tool", "pricing"])
def test_rejects_wrong_chronology_tool_or_pricing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    if mutation == "chronology":
        chronology = Path(values["chronology_path"])
        record = json.loads(chronology.read_bytes())
        record["captured_at"] = "2026-07-11T12:00:00Z"
        _write(chronology, record)
        match = "occurs after"
    elif mutation == "tool":
        values["tool_git_sha"] = "0" * 40
        match = "exact pending amendment"
    else:
        pricing = Path(values["pricing_snapshot_path"])
        record = json.loads(pricing.read_bytes())
        record["requested_model"] = "wrong-model"
        _write(pricing, record)
        cases = Path(values["cases_preparation_path"])
        cases_record = json.loads(cases.read_bytes())
        cases_record["inputs"]["pricing_snapshot"]["sha256"] = hashlib.sha256(
            pricing.read_bytes()
        ).hexdigest()
        _write(cases, cases_record)
        match = "pricing|Pricing"
    with pytest.raises(PolicyRejection, match=match):
        _prepare(values)


def test_rejects_fabricated_mapping_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    packet = Path(values["_mapping_root"]) / "packet-001.json"
    record = json.loads(packet.read_bytes())
    record["reviews"] = [{"reviewer_id": "fake-human", "verdict": "approved"}]
    _write(packet, record)
    mapping = Path(values["mapping_preparation_path"])
    mapping_record = json.loads(mapping.read_bytes())
    mapping_record["cases"][0]["packet"]["sha256"] = hashlib.sha256(
        packet.read_bytes()
    ).hexdigest()
    _write(mapping, mapping_record)
    with pytest.raises(PolicyRejection, match="no reviews"):
        _prepare(values)


def test_rejects_toctou_swap_after_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    verify = evidence_module.verify_v02_exact_image_capability_index

    def swap(*args: object, **kwargs: object) -> SimpleNamespace:
        authority = verify(*args, **kwargs)
        _write(Path(values["capability_index_path"]), {"swapped": True})
        return authority

    monkeypatch.setattr(evidence_module, "verify_v02_exact_image_capability_index", swap)
    with pytest.raises(PolicyRejection, match="changed after verification"):
        _prepare(values)


def test_schemas_are_mirrored() -> None:
    for name in (
        "benchmark-v021-automated-evidence.schema.json",
        "benchmark-v021-automated-preregistration.schema.json",
    ):
        public = Path("schemas") / name
        bundled = Path("src/reproassert/schemas") / name
        assert public.read_bytes() == bundled.read_bytes()
        Draft202012Validator.check_schema(json.loads(public.read_text()))
