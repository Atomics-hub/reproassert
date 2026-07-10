from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from jsonschema import Draft202012Validator

import reproassert.benchmark_v02_cohort as cohort
from reproassert.errors import PolicyRejection


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _receipt() -> dict[str, object]:
    audits: list[dict[str, object]] = []
    joined: list[dict[str, object]] = []
    projections: list[dict[str, object]] = []
    ordinals = {
        "astropy__astropy-12907": 1,
        "astropy__astropy-7166": 15,
    }
    next_ordinal = 100
    for row_ordinal, seed in enumerate(cohort._SEEDS):
        text = f"issue snapshot for {seed.case_id}"
        membership_ordinal = ordinals.get(seed.instance_id, next_ordinal)
        next_ordinal += 1
        identity = {
            "base_commit": seed.base_sha,
            "instance_id": seed.instance_id,
            "repo": seed.repo,
        }
        audits.append(
            {
                "base_commit": seed.base_sha,
                "difficulty": cohort._DIFFICULTY_TO_UPSTREAM[seed.difficulty],
                "direct_own_fixing_pr_reference": False,
                "instance_id": seed.instance_id,
                "issue_text_bytes": len(text),
                "issue_text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "oracle_leak_free": True,
                "production_added_line_overlap": False,
                "repo": seed.repo,
                "row_ordinal": row_ordinal,
                "test_added_line_overlap": False,
            }
        )
        joined.append(
            {
                "identity_sha256": hashlib.sha256(_canonical(identity)).hexdigest(),
                "instance_id": seed.instance_id,
                "source_dataset_row_ordinal": row_ordinal,
                "source_dataset_row_sha256": hashlib.sha256(seed.instance_id.encode()).hexdigest(),
                "tdd_membership_ordinal": membership_ordinal,
            }
        )
        projections.append({"instance_id": seed.instance_id, "problem_statement": text})
    return {
        "dataset": {
            "issue_projections": projections,
            "joined_tdd_rows": joined,
            "leak_audit_rows": audits,
        },
        "upstream": {
            "source_dataset": {"git_sha": "1" * 40},
            "verification": {"object_witness_sha256": "2" * 64},
        },
    }


def _render(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, receipt: dict[str, object] | None = None
) -> tuple[bytes, Path]:
    prepared = _receipt() if receipt is None else receipt
    monkeypatch.setattr(cohort, "load_prepared_v02_dataset_receipt", lambda _path: prepared)
    content = cohort.render_prepared_v02_leak_audited_cohort_plan(tmp_path / "receipt.json")
    path = tmp_path / "cohort-plan.json"
    path.write_bytes(content)
    return content, path


def test_plan_is_deterministic_leak_free_and_contains_two_replacements(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    content, path = _render(monkeypatch, tmp_path)
    plan = cohort.load_v02_leak_audited_cohort_plan(path)

    assert plan["status"] == "prepared_not_production_eligible"
    assert plan["difficulty_split"] == {"15m_to_1h": 6, "lt_15m": 14}
    assert plan["repository_count"] == 10
    cases = cast(list[dict[str, object]], plan["cases"])
    assert cases[1]["instance_id"] == "astropy__astropy-7166"
    assert cases[1]["replaced_instance_id"] == "astropy__astropy-14995"
    assert cases[1]["tdd_membership_ordinal"] == 15
    assert cases[2]["instance_id"] == "astropy__astropy-12907"
    assert cases[2]["replaced_instance_id"] == "astropy__astropy-7606"
    assert cases[2]["tdd_membership_ordinal"] == 1
    for forbidden in (b'"hints_text"', b'"patch"', b'"problem_statement"', b'"test_patch"'):
        assert forbidden not in content
    assert content == cohort.render_prepared_v02_leak_audited_cohort_plan(tmp_path / "receipt.json")

    root_schema = Path("schemas/benchmark-v02-leak-audited-cohort-plan.schema.json")
    bundled_schema = Path(
        "src/reproassert/schemas/benchmark-v02-leak-audited-cohort-plan.schema.json"
    )
    assert root_schema.read_bytes() == bundled_schema.read_bytes()
    Draft202012Validator(json.loads(root_schema.read_text())).validate(plan)


@pytest.mark.parametrize(
    "field",
    [
        "direct_own_fixing_pr_reference",
        "production_added_line_overlap",
        "test_added_line_overlap",
    ],
)
def test_plan_rejects_any_selected_oracle_leak(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, field: str
) -> None:
    receipt = _receipt()
    audits = cast(
        list[dict[str, object]],
        cast(dict[str, object], receipt["dataset"])["leak_audit_rows"],
    )
    audits[5][field] = True
    audits[5]["oracle_leak_free"] = False
    monkeypatch.setattr(cohort, "load_prepared_v02_dataset_receipt", lambda _path: receipt)
    with pytest.raises(PolicyRejection, match="oracle-leak"):
        cohort.render_prepared_v02_leak_audited_cohort_plan(tmp_path / "receipt.json")


def test_plan_rejects_nonminimal_replacement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    receipt = _receipt()
    dataset = cast(dict[str, object], receipt["dataset"])
    audits = cast(list[dict[str, object]], dataset["leak_audit_rows"])
    joined = cast(list[dict[str, object]], dataset["joined_tdd_rows"])
    candidate = dict(audits[1])
    candidate.update(
        {
            "instance_id": "astropy__astropy-6000",
            "issue_text_sha256": "a" * 64,
            "row_ordinal": 499,
        }
    )
    audits.append(candidate)
    joined.append(
        {
            "identity_sha256": "b" * 64,
            "instance_id": "astropy__astropy-6000",
            "source_dataset_row_ordinal": 499,
            "source_dataset_row_sha256": "c" * 64,
            "tdd_membership_ordinal": 2,
        }
    )
    monkeypatch.setattr(cohort, "load_prepared_v02_dataset_receipt", lambda _path: receipt)
    with pytest.raises(PolicyRejection, match="lowest eligible"):
        cohort.render_prepared_v02_leak_audited_cohort_plan(tmp_path / "receipt.json")


def test_prepared_issue_projection_has_explicit_chronology_and_contamination_labels(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    receipt = _receipt()
    _, path = _render(monkeypatch, tmp_path, receipt)
    projection = json.loads(
        cohort.render_prepared_v02_issue_snapshot_projection(
            tmp_path / "receipt.json", path, case_id="rk-v0.2-002"
        )
    )

    assert projection["status"] == "preparation_only_not_campaign_eligible"
    assert projection["issue_text_source"] == "dataset_snapshot_at_pinned_commit"
    assert projection["issue_text_chronology"] == "chronology_unproven"
    assert (
        projection["historical_public_contamination"] == "historical_public_contamination_exposed"
    )
    assert (
        projection["generator_claim_ceiling"]
        == "generated_against_exact_buggy_base_with_historical_fix_hidden"
    )
    assert (
        projection["issue_url_provenance"]
        == "current_fixing_pr_body_mapping_unauthenticated_chronology_unproven"
    )
    assert "patch" not in projection


def test_plan_and_projection_fail_closed_on_tampering_or_missing_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    receipt = _receipt()
    content, path = _render(monkeypatch, tmp_path, receipt)
    decoded = json.loads(content)
    decoded["cases"][0]["issue_url"] = "https://example.invalid"
    path.write_bytes(_canonical(decoded) + b"\n")
    with pytest.raises(PolicyRejection, match="digest"):
        cohort.load_v02_leak_audited_cohort_plan(path)

    _, valid_path = _render(monkeypatch, tmp_path, receipt)
    dataset = cast(dict[str, object], receipt["dataset"])
    dataset["issue_projections"] = []
    with pytest.raises(PolicyRejection, match="not requested"):
        cohort.render_prepared_v02_issue_snapshot_projection(
            tmp_path / "receipt.json", valid_path, case_id="rk-v0.2-001"
        )


def test_attested_selection_freeze_is_selection_only_and_keeps_results_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    receipt = _receipt()
    _, plan_path = _render(monkeypatch, tmp_path, receipt)
    attested = SimpleNamespace(
        boundary_attestation_sha256="3" * 64,
        image_digest="sha256:" + "4" * 64,
        parser_receipt=b"private receipt\n",
        parser_receipt_sha256=hashlib.sha256(b"private receipt\n").hexdigest(),
        upstream_evidence_sha256="5" * 64,
    )
    monkeypatch.setattr(cohort, "require_attested_v02_dataset_parse", lambda value: value)

    content = cohort.render_attested_v02_selection_freeze(attested, plan_path)  # type: ignore[arg-type]
    freeze_path = tmp_path / "selection-freeze.json"
    freeze_path.write_bytes(content)
    freeze = cohort.load_v02_selection_freeze(freeze_path)

    assert freeze["status"] == "selection_frozen_not_campaign_preregistered"
    assert freeze["production_boundary_verified"] is True
    assert freeze["results"] == {
        "benchmark_cases_executed": 0,
        "l1_valid_reproductions": 0,
        "l2_semantic_valid_reproductions": 0,
        "maintainer_validations": 0,
    }
    assert freeze["privacy"]["generator_issue_text_published"] is False
    root_schema = Path("schemas/benchmark-v02-selection-freeze.schema.json")
    bundled_schema = Path("src/reproassert/schemas/benchmark-v02-selection-freeze.schema.json")
    assert root_schema.read_bytes() == bundled_schema.read_bytes()
    Draft202012Validator(json.loads(root_schema.read_text())).validate(freeze)


def test_checked_in_selection_artifacts_are_canonical_safe_and_schema_valid() -> None:
    plan_path = Path("benchmarks/v0.2-draft/leak-audited-cohort-plan.json")
    freeze_path = Path("benchmarks/v0.2-draft/selection-freeze.json")
    attestation_path = Path("benchmarks/v0.2-draft/dataset-parser-boundary-attestation.json")
    plan = cohort.load_v02_leak_audited_cohort_plan(plan_path)
    freeze = cohort.load_v02_selection_freeze(freeze_path)
    attestation = json.loads(attestation_path.read_text())
    assert freeze["cohort_plan_sha256"] == plan["cohort_plan_sha256"]
    assert (
        freeze["dataset_parser_boundary_attestation_sha256"]
        == hashlib.sha256(attestation_path.read_bytes()).hexdigest()
    )
    assert freeze["results"]["benchmark_cases_executed"] == 0
    assert freeze["privacy"]["generator_issue_text_published"] is False
    Draft202012Validator(
        json.loads(Path("schemas/benchmark-v02-leak-audited-cohort-plan.schema.json").read_text())
    ).validate(plan)
    Draft202012Validator(
        json.loads(Path("schemas/benchmark-v02-selection-freeze.schema.json").read_text())
    ).validate(freeze)
    attestation_schema = Path("schemas/benchmark-v02-dataset-container-attestation.schema.json")
    bundled_attestation_schema = Path(
        "src/reproassert/schemas/benchmark-v02-dataset-container-attestation.schema.json"
    )
    assert attestation_schema.read_bytes() == bundled_attestation_schema.read_bytes()
    Draft202012Validator(json.loads(attestation_schema.read_text())).validate(attestation)
