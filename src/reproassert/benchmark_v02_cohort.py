"""Deterministic oracle-leak audit and dataset-snapshot projection for benchmark v0.2."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from reproassert.benchmark_v02_dataset import load_prepared_v02_dataset_receipt
from reproassert.benchmark_v02_dataset_sandbox import (
    AttestedV02DatasetParse,
    require_attested_v02_dataset_parse,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, write_bytes_exclusive

LEAK_AUDITED_COHORT_PLAN_ALGORITHM = "reproassert-v02-leak-audited-cohort-plan-v1"
DATASET_ISSUE_SNAPSHOT_ALGORITHM = "reproassert-v02-dataset-issue-snapshot-v1"
SELECTION_FREEZE_ALGORITHM = "reproassert-v02-selection-freeze-v1"
COHORT_PLAN_STATUS = "prepared_not_production_eligible"
_MAX_PLAN_BYTES = 512 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CASE_ID = re.compile(r"rk-v0\.2-(?:00[1-9]|01[0-9]|020)\Z")
_DIFFICULTY_TO_UPSTREAM = {
    "lt_15m": "<15 min fix",
    "15m_to_1h": "15 min - 1 hour",
}
_REPLACEMENT_RULE = (
    "lowest_tdd_membership_ordinal_same_repo_and_difficulty_passing_mechanical_oracle_audit"
)


@dataclass(frozen=True)
class _Seed:
    case_id: str
    repo: str
    issue_url: str
    base_sha: str
    difficulty: str
    instance_id: str
    replaced_instance_id: str | None = None


_SEEDS = (
    _Seed(
        "rk-v0.2-001",
        "astropy/astropy",
        "https://github.com/astropy/astropy/issues/14305",
        "cdb66059a2feb44ee49021874605ba90801f9986",
        "lt_15m",
        "astropy__astropy-14309",
    ),
    _Seed(
        "rk-v0.2-002",
        "astropy/astropy",
        "https://github.com/astropy/astropy/issues/7162",
        "26d147868f8a891a6009a25cd6a8576d2e1bd747",
        "lt_15m",
        "astropy__astropy-7166",
        "astropy__astropy-14995",
    ),
    _Seed(
        "rk-v0.2-003",
        "astropy/astropy",
        "https://github.com/astropy/astropy/issues/12906",
        "d16bfe05a744909de4b27f5875fe0d4ed41ce607",
        "15m_to_1h",
        "astropy__astropy-12907",
        "astropy__astropy-7606",
    ),
    _Seed(
        "rk-v0.2-004",
        "matplotlib/matplotlib",
        "https://github.com/matplotlib/matplotlib/issues/24127",
        "af39f1edffcd828f05cfdd04f2e59506bb4a27bc",
        "lt_15m",
        "matplotlib__matplotlib-24149",
    ),
    _Seed(
        "rk-v0.2-005",
        "matplotlib/matplotlib",
        "https://github.com/matplotlib/matplotlib/issues/25300",
        "430fb1db88843300fb4baae3edc499bbfe073b0c",
        "lt_15m",
        "matplotlib__matplotlib-25311",
    ),
    _Seed(
        "rk-v0.2-006",
        "scikit-learn/scikit-learn",
        "https://github.com/scikit-learn/scikit-learn/issues/13070",
        "1c8668b0a021832386470ddf740d834e02c66f69",
        "lt_15m",
        "scikit-learn__scikit-learn-13142",
    ),
    _Seed(
        "rk-v0.2-007",
        "scikit-learn/scikit-learn",
        "https://github.com/scikit-learn/scikit-learn/issues/13314",
        "37b0e66c871e8fb032a9c7086b2a1d5419838154",
        "lt_15m",
        "scikit-learn__scikit-learn-13328",
    ),
    _Seed(
        "rk-v0.2-008",
        "scikit-learn/scikit-learn",
        "https://github.com/scikit-learn/scikit-learn/issues/13976",
        "6ab8c86c383dd847a1be7103ad115f174fe23ffd",
        "15m_to_1h",
        "scikit-learn__scikit-learn-14053",
    ),
    _Seed(
        "rk-v0.2-009",
        "pytest-dev/pytest",
        "https://github.com/pytest-dev/pytest/issues/5606",
        "cb828ebe70b4fa35cd5f9a7ee024272237eab351",
        "15m_to_1h",
        "pytest-dev__pytest-5631",
    ),
    _Seed(
        "rk-v0.2-010",
        "pytest-dev/pytest",
        "https://github.com/pytest-dev/pytest/issues/7981",
        "a7e38c5c61928033a2dc1915cbee8caa8544a4d0",
        "lt_15m",
        "pytest-dev__pytest-7982",
    ),
    _Seed(
        "rk-v0.2-011",
        "pydata/xarray",
        "https://github.com/pydata/xarray/issues/4074",
        "19b088636eb7d3f65ab7a1046ac672e0689371d8",
        "lt_15m",
        "pydata__xarray-4075",
    ),
    _Seed(
        "rk-v0.2-012",
        "pydata/xarray",
        "https://github.com/pydata/xarray/issues/4049",
        "a64cf2d5476e7bbda099b34c40b7be1880dbd39a",
        "lt_15m",
        "pydata__xarray-4094",
    ),
    _Seed(
        "rk-v0.2-013",
        "pydata/xarray",
        "https://github.com/pydata/xarray/issues/6931",
        "c4e40d991c28be51de9ac560ce895ac7f9b14924",
        "15m_to_1h",
        "pydata__xarray-6938",
    ),
    _Seed(
        "rk-v0.2-014",
        "psf/requests",
        "https://github.com/psf/requests/issues/1920",
        "3c88e520da24ae6f736929a750876e7654accc3d",
        "lt_15m",
        "psf__requests-1921",
    ),
    _Seed(
        "rk-v0.2-015",
        "psf/requests",
        "https://github.com/psf/requests/issues/2930",
        "5f7a3a74aab1625c2bb65f643197ee885e3da576",
        "15m_to_1h",
        "psf__requests-2931",
    ),
    _Seed(
        "rk-v0.2-016",
        "sympy/sympy",
        "https://github.com/sympy/sympy/issues/15344",
        "9ef28fba5b4d6d0168237c9c005a550e6dc27d81",
        "lt_15m",
        "sympy__sympy-15345",
    ),
    _Seed(
        "rk-v0.2-017",
        "sympy/sympy",
        "https://github.com/sympy/sympy/issues/15873",
        "b506169ad727ee39cb3d60c8b3ff5e315d443d8e",
        "lt_15m",
        "sympy__sympy-15875",
    ),
    _Seed(
        "rk-v0.2-018",
        "pallets/flask",
        "https://github.com/pallets/flask/issues/5010",
        "7ee9ceb71e868944a46e1ff00b506772a53a4f1d",
        "lt_15m",
        "pallets__flask-5014",
    ),
    _Seed(
        "rk-v0.2-019",
        "mwaskom/seaborn",
        "https://github.com/mwaskom/seaborn/issues/3174",
        "22cdfb0c93f8ec78492d87edb810f10cb7f57a31",
        "15m_to_1h",
        "mwaskom__seaborn-3187",
    ),
    _Seed(
        "rk-v0.2-020",
        "pylint-dev/pylint",
        "https://github.com/pylint-dev/pylint/issues/4901",
        "40cc2ffd7887959157aaf469e09585ec2be7f528",
        "lt_15m",
        "pylint-dev__pylint-4970",
    ),
)

_ORIGINAL_INSTANCE_IDS = frozenset(
    {
        "astropy__astropy-14309",
        "astropy__astropy-14995",
        "astropy__astropy-7606",
        "matplotlib__matplotlib-24149",
        "matplotlib__matplotlib-25311",
        "scikit-learn__scikit-learn-13142",
        "scikit-learn__scikit-learn-13328",
        "scikit-learn__scikit-learn-14053",
        "pytest-dev__pytest-5631",
        "pytest-dev__pytest-7982",
        "pydata__xarray-4075",
        "pydata__xarray-4094",
        "pydata__xarray-6938",
        "psf__requests-1921",
        "psf__requests-2931",
        "sympy__sympy-15345",
        "sympy__sympy-15875",
        "pallets__flask-5014",
        "mwaskom__seaborn-3187",
        "pylint-dev__pylint-4970",
    }
)


def render_prepared_v02_leak_audited_cohort_plan(receipt_path: Path) -> bytes:
    """Build the fixed 20-case plan from a host-native preparation receipt.

    The plan contains no problem statements, hints, production patches, or developer-test bytes.
    It remains explicitly ineligible for a scored campaign until regenerated from the attested
    container boundary.
    """

    receipt = load_prepared_v02_dataset_receipt(receipt_path)
    dataset = cast(dict[str, object], receipt["dataset"])
    audits = cast(list[dict[str, object]], dataset["leak_audit_rows"])
    joined = cast(list[dict[str, object]], dataset["joined_tdd_rows"])
    audit_by_id = {cast(str, item["instance_id"]): item for item in audits}
    joined_by_id = {cast(str, item["instance_id"]): item for item in joined}
    _verify_replacement_rule(audit_by_id, joined_by_id)

    cases: list[dict[str, object]] = []
    for seed in _SEEDS:
        audit = audit_by_id.get(seed.instance_id)
        membership = joined_by_id.get(seed.instance_id)
        if audit is None or membership is None:
            raise _reject("The fixed cohort case is absent from the exact TDD-Bench join.")
        _require_safe_seed(seed, audit, membership)
        audit_record = {
            "direct_own_fixing_pr_reference": False,
            "minimum_exact_added_line_characters": 40,
            "oracle_leak_free": True,
            "production_added_line_overlap": False,
            "test_added_line_overlap": False,
        }
        case: dict[str, object] = {
            "base_sha": seed.base_sha,
            "case_id": seed.case_id,
            "difficulty": seed.difficulty,
            "instance_id": seed.instance_id,
            "issue_text_sha256": audit["issue_text_sha256"],
            "issue_url": seed.issue_url,
            "issue_url_provenance": (
                "current_fixing_pr_body_mapping_unauthenticated_chronology_unproven"
                if seed.replaced_instance_id
                else "controller_selected_v0.1_mapping_chronology_unproven"
            ),
            "oracle_leak_audit": audit_record,
            "replaced_instance_id": seed.replaced_instance_id,
            "replacement_rule": (
                _REPLACEMENT_RULE if seed.replaced_instance_id else "not_applicable"
            ),
            "repo": seed.repo,
            "selection_origin": (
                "deterministic_tdd_membership_replacement"
                if seed.replaced_instance_id
                else "v0.1_migration"
            ),
            "source_dataset_row_ordinal": membership["source_dataset_row_ordinal"],
            "tdd_membership_ordinal": membership["tdd_membership_ordinal"],
        }
        case["case_plan_sha256"] = hashlib.sha256(_canonical(case)).hexdigest()
        cases.append(case)

    record: dict[str, object] = {
        "algorithm": LEAK_AUDITED_COHORT_PLAN_ALGORITHM,
        "case_count": 20,
        "cases": cases,
        "difficulty_split": {"15m_to_1h": 6, "lt_15m": 14},
        "issue_text_policy": {
            "generator_claim_ceiling": (
                "generated_against_exact_buggy_base_with_historical_fix_hidden"
            ),
            "historical_public_contamination": "historical_public_contamination_exposed",
            "issue_text_chronology": "chronology_unproven",
            "issue_text_source": "dataset_snapshot_at_pinned_commit",
            "issue_text_source_commit": cast(
                dict[str, object],
                cast(dict[str, object], receipt["upstream"])["source_dataset"],
            )["git_sha"],
            "source_dataset_object_witness_sha256": cast(
                dict[str, object], cast(dict[str, object], receipt["upstream"])["verification"]
            )["object_witness_sha256"],
        },
        "oracle_leak_policy": {
            "direct_own_fixing_pr_reference": "reject",
            "exact_production_added_line_overlap_at_least_40_chars": "quarantine",
            "exact_test_added_line_overlap_at_least_40_chars": "quarantine",
        },
        "repository_count": 10,
        "security": {
            "developer_test_bytes_exposed": False,
            "hints_text_exposed": False,
            "production_patch_bytes_exposed": False,
        },
        "selection_method": (
            "v0.1_migration_with_two_lowest_membership_same_repo_difficulty_leak_free_replacements"
        ),
        "status": COHORT_PLAN_STATUS,
    }
    record["cohort_plan_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
    return _canonical(record) + b"\n"


def load_v02_leak_audited_cohort_plan(path: Path) -> dict[str, object]:
    """Validate the deterministic plan envelope and all public non-leakage invariants."""

    raw = _read_bounded(Path(path), _MAX_PLAN_BYTES, "leak-audited cohort plan")
    root = _load_canonical(raw, "leak-audited cohort plan")
    expected_keys = {
        "algorithm",
        "case_count",
        "cases",
        "cohort_plan_sha256",
        "difficulty_split",
        "issue_text_policy",
        "oracle_leak_policy",
        "repository_count",
        "security",
        "selection_method",
        "status",
    }
    if set(root) != expected_keys or root.get("algorithm") != LEAK_AUDITED_COHORT_PLAN_ALGORITHM:
        raise _reject("Leak-audited cohort plan fields are invalid.")
    observed_hash = root.get("cohort_plan_sha256")
    envelope = {name: item for name, item in root.items() if name != "cohort_plan_sha256"}
    if observed_hash != hashlib.sha256(_canonical(envelope)).hexdigest():
        raise _reject("Leak-audited cohort plan digest is invalid.")
    if (
        root.get("status") != COHORT_PLAN_STATUS
        or root.get("case_count") != 20
        or root.get("repository_count") != 10
        or root.get("difficulty_split") != {"15m_to_1h": 6, "lt_15m": 14}
        or root.get("security")
        != {
            "developer_test_bytes_exposed": False,
            "hints_text_exposed": False,
            "production_patch_bytes_exposed": False,
        }
    ):
        raise _reject("Leak-audited cohort plan declaration is invalid.")
    cases = root.get("cases")
    if not isinstance(cases, list) or len(cases) != 20:
        raise _reject("Leak-audited cohort plan does not contain exactly 20 cases.")
    for ordinal, item in enumerate(cases, start=1):
        _validate_case(item, ordinal)
    return root


def render_attested_v02_selection_freeze(
    attested_parse: AttestedV02DatasetParse, cohort_plan_path: Path
) -> bytes:
    """Freeze selection only after byte-for-byte rederivation from the attested parse.

    This is not a campaign freeze, preregistration, model run, or result artifact.
    """

    attested = require_attested_v02_dataset_parse(attested_parse)
    plan_bytes = _read_bounded(Path(cohort_plan_path), _MAX_PLAN_BYTES, "cohort plan")
    plan = load_v02_leak_audited_cohort_plan(cohort_plan_path)
    with tempfile.TemporaryDirectory(prefix="reproassert-v02-selection-freeze-") as temporary:
        receipt_path = Path(temporary).resolve(strict=True) / "private-receipt.json"
        write_bytes_exclusive(receipt_path, attested.parser_receipt)
        expected_plan = render_prepared_v02_leak_audited_cohort_plan(receipt_path)
        receipt = load_prepared_v02_dataset_receipt(receipt_path)
    if plan_bytes != expected_plan:
        raise _reject("Cohort plan differs from the attested dataset parser derivation.")
    upstream = cast(dict[str, object], receipt["upstream"])
    source = cast(dict[str, object], upstream["source_dataset"])
    verification = cast(dict[str, object], upstream["verification"])
    record: dict[str, object] = {
        "algorithm": SELECTION_FREEZE_ALGORITHM,
        "case_count": 20,
        "cohort_plan_sha256": plan["cohort_plan_sha256"],
        "dataset_parser_boundary_attestation_sha256": (attested.boundary_attestation_sha256),
        "dataset_parser_image_digest": attested.image_digest,
        "dataset_parser_private_receipt_sha256": attested.parser_receipt_sha256,
        "issue_text_source": "dataset_snapshot_at_pinned_commit",
        "issue_text_source_commit": source["git_sha"],
        "oracle_leak_audit_passed_cases": 20,
        "privacy": {
            "developer_test_bytes_published": False,
            "generator_issue_text_published": False,
            "hints_text_published": False,
            "production_patch_bytes_published": False,
        },
        "production_boundary_verified": True,
        "results": {
            "benchmark_cases_executed": 0,
            "l1_valid_reproductions": 0,
            "l2_semantic_valid_reproductions": 0,
            "maintainer_validations": 0,
        },
        "status": "selection_frozen_not_campaign_preregistered",
        "upstream_evidence_sha256": attested.upstream_evidence_sha256,
        "upstream_object_witness_sha256": verification["object_witness_sha256"],
    }
    record["selection_freeze_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
    return _canonical(record) + b"\n"


def load_v02_selection_freeze(path: Path) -> dict[str, object]:
    """Validate the public selection-only freeze and its explicit zero-result state."""

    raw = _read_bounded(Path(path), _MAX_PLAN_BYTES, "selection freeze")
    root = _load_canonical(raw, "selection freeze")
    expected_keys = {
        "algorithm",
        "case_count",
        "cohort_plan_sha256",
        "dataset_parser_boundary_attestation_sha256",
        "dataset_parser_image_digest",
        "dataset_parser_private_receipt_sha256",
        "issue_text_source",
        "issue_text_source_commit",
        "oracle_leak_audit_passed_cases",
        "privacy",
        "production_boundary_verified",
        "results",
        "selection_freeze_sha256",
        "status",
        "upstream_evidence_sha256",
        "upstream_object_witness_sha256",
    }
    digest = root.get("selection_freeze_sha256")
    envelope = {name: item for name, item in root.items() if name != "selection_freeze_sha256"}
    if (
        set(root) != expected_keys
        or root.get("algorithm") != SELECTION_FREEZE_ALGORITHM
        or digest != hashlib.sha256(_canonical(envelope)).hexdigest()
        or root.get("case_count") != 20
        or root.get("oracle_leak_audit_passed_cases") != 20
        or root.get("production_boundary_verified") is not True
        or root.get("status") != "selection_frozen_not_campaign_preregistered"
        or root.get("results")
        != {
            "benchmark_cases_executed": 0,
            "l1_valid_reproductions": 0,
            "l2_semantic_valid_reproductions": 0,
            "maintainer_validations": 0,
        }
    ):
        raise _reject("Selection freeze is invalid or overstates benchmark progress.")
    return root


def render_prepared_v02_issue_snapshot_projection(
    receipt_path: Path, cohort_plan_path: Path, *, case_id: str
) -> bytes:
    """Render one safe dataset issue snapshot, explicitly preparation-only."""

    plan = load_v02_leak_audited_cohort_plan(cohort_plan_path)
    if not isinstance(case_id, str) or _CASE_ID.fullmatch(case_id) is None:
        raise _reject("Issue snapshot case ID is invalid.")
    case = next(
        (
            cast(dict[str, object], item)
            for item in cast(list[object], plan["cases"])
            if isinstance(item, dict) and item.get("case_id") == case_id
        ),
        None,
    )
    if case is None:
        raise _reject("Issue snapshot case is absent from the leak-audited plan.")
    receipt = load_prepared_v02_dataset_receipt(receipt_path)
    projections = cast(
        list[object], cast(dict[str, object], receipt["dataset"])["issue_projections"]
    )
    projection = next(
        (
            cast(dict[str, object], item)
            for item in projections
            if isinstance(item, dict) and item.get("instance_id") == case["instance_id"]
        ),
        None,
    )
    if projection is None:
        raise _reject("Safe issue text was not requested from the pinned parser.")
    text = cast(str, projection["problem_statement"])
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != case["issue_text_sha256"]:
        raise _reject("Issue snapshot text differs from the leak-audited commitment.")
    record: dict[str, object] = {
        "algorithm": DATASET_ISSUE_SNAPSHOT_ALGORITHM,
        "base_sha": case["base_sha"],
        "case_id": case_id,
        "generator_claim_ceiling": (
            "generated_against_exact_buggy_base_with_historical_fix_hidden"
        ),
        "historical_public_contamination": "historical_public_contamination_exposed",
        "instance_id": case["instance_id"],
        "issue_text": text,
        "issue_text_chronology": "chronology_unproven",
        "issue_text_sha256": case["issue_text_sha256"],
        "issue_text_source": "dataset_snapshot_at_pinned_commit",
        "issue_url": case["issue_url"],
        "issue_url_provenance": case["issue_url_provenance"],
        "oracle_leak_audit": case["oracle_leak_audit"],
        "repo": case["repo"],
        "status": "preparation_only_not_campaign_eligible",
    }
    record["projection_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
    return _canonical(record) + b"\n"


def _verify_replacement_rule(
    audits: dict[str, dict[str, object]], joined: dict[str, dict[str, object]]
) -> None:
    for seed in (item for item in _SEEDS if item.replaced_instance_id is not None):
        upstream_difficulty = _DIFFICULTY_TO_UPSTREAM[seed.difficulty]
        candidates = sorted(
            (
                cast(int, joined[instance_id]["tdd_membership_ordinal"]),
                instance_id,
            )
            for instance_id, audit in audits.items()
            if instance_id in joined
            and instance_id not in _ORIGINAL_INSTANCE_IDS
            and audit.get("repo") == seed.repo
            and audit.get("difficulty") == upstream_difficulty
            and audit.get("oracle_leak_free") is True
        )
        if not candidates or candidates[0][1] != seed.instance_id:
            raise _reject("A deterministic replacement is not the lowest eligible TDD member.")


def _require_safe_seed(
    seed: _Seed, audit: dict[str, object], membership: dict[str, object]
) -> None:
    identity = {
        "base_commit": seed.base_sha,
        "instance_id": seed.instance_id,
        "repo": seed.repo,
    }
    if (
        audit.get("base_commit") != seed.base_sha
        or audit.get("repo") != seed.repo
        or audit.get("difficulty") != _DIFFICULTY_TO_UPSTREAM[seed.difficulty]
        or audit.get("oracle_leak_free") is not True
        or any(
            audit.get(name) is not False
            for name in (
                "direct_own_fixing_pr_reference",
                "production_added_line_overlap",
                "test_added_line_overlap",
            )
        )
        or membership.get("identity_sha256") != hashlib.sha256(_canonical(identity)).hexdigest()
        or membership.get("source_dataset_row_ordinal") != audit.get("row_ordinal")
    ):
        raise _reject("A fixed cohort case fails its identity or mechanical oracle-leak audit.")


def _validate_case(raw: object, ordinal: int) -> None:
    keys = {
        "base_sha",
        "case_id",
        "case_plan_sha256",
        "difficulty",
        "instance_id",
        "issue_text_sha256",
        "issue_url",
        "issue_url_provenance",
        "oracle_leak_audit",
        "replaced_instance_id",
        "replacement_rule",
        "repo",
        "selection_origin",
        "source_dataset_row_ordinal",
        "tdd_membership_ordinal",
    }
    if not isinstance(raw, dict) or set(raw) != keys:
        raise _reject("Leak-audited cohort case fields are invalid.")
    expected_id = f"rk-v0.2-{ordinal:03d}"
    digest = raw.get("case_plan_sha256")
    envelope = {name: item for name, item in raw.items() if name != "case_plan_sha256"}
    audit = raw.get("oracle_leak_audit")
    if (
        raw.get("case_id") != expected_id
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or digest != hashlib.sha256(_canonical(envelope)).hexdigest()
        or not isinstance(audit, dict)
        or audit.get("oracle_leak_free") is not True
        or any(
            audit.get(name) is not False
            for name in (
                "direct_own_fixing_pr_reference",
                "production_added_line_overlap",
                "test_added_line_overlap",
            )
        )
    ):
        raise _reject("Leak-audited cohort case is inconsistent.")


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            content = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label} could not be read safely.") from exc
    if len(content) > limit:
        raise _reject(f"{label} exceeds its byte limit.")
    return content


def _load_canonical(content: bytes, label: str) -> dict[str, object]:
    try:
        decoded = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _reject(f"{label} is invalid JSON.") from exc
    if not isinstance(decoded, dict) or content != _canonical(decoded) + b"\n":
        raise _reject(f"{label} is not canonical JSON.")
    return cast(dict[str, object], decoded)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _reject("Cohort evidence cannot be encoded as canonical JSON.") from exc


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_cohort", message)
