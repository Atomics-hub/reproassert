from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

import reproassert.benchmark_v02_exact_preregistration as exact
from reproassert.errors import PolicyRejection

TOOL_SHA = "a" * 40
MANIFEST_SHA = "b" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value))
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _private(path: Path) -> Path:
    path.mkdir()
    os.chmod(path, 0o700)
    return path


def _fixtures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    root = _private(tmp_path / "private")
    prep_root = root / "cases"
    prep_root.mkdir()
    mapping_root = root / "mapping"
    mapping_root.mkdir()
    plan_cases: list[dict[str, object]] = []
    package_refs: list[dict[str, object]] = []
    mapping_rows: list[dict[str, object]] = []
    consensus_rows: list[dict[str, object]] = []
    capability_rows: list[dict[str, object]] = []
    for number in range(1, 21):
        case_id = f"rk-v0.2-{number:03d}"
        repo = f"owner{number % 10}/repo{number % 10}"
        issue_url = f"https://github.com/{repo}/issues/{number}"
        base_sha = f"{number:040x}"
        instance_id = f"owner{number % 10}__repo{number % 10}-{number}"
        plan_cases.append(
            {
                "base_sha": base_sha,
                "case_id": case_id,
                "difficulty": "15m_to_1h" if number in {3, 8, 9, 13, 15, 19} else "lt_15m",
                "instance_id": instance_id,
                "issue_url": issue_url,
                "repo": repo,
            }
        )
        projection_sha = hashlib.sha256(f"projection:{case_id}".encode()).hexdigest()
        request_input = json.dumps(
            {
                "candidate_contract": {
                    "profile": "sympy-native-v1" if number in {16, 17} else "pytest-v1"
                },
                "case_id": case_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        request = {
            "generator_input": {
                "issue_projection_sha256": projection_sha,
                "source_archive_sha256": hashlib.sha256(f"archive:{case_id}".encode()).hexdigest(),
                "source_tree_sha256": hashlib.sha256(f"tree:{case_id}".encode()).hexdigest(),
            },
            "outbound_request_sha256": hashlib.sha256(f"outbound:{case_id}".encode()).hexdigest(),
            "provider_request": {"input": request_input},
            "rendered_input_sha256": hashlib.sha256(request_input.encode()).hexdigest(),
        }
        request_path = _write(prep_root / "requests" / f"{case_id}.json", request)
        package = {
            "base_sha": base_sha,
            "case_id": case_id,
            "generator_projection": {
                "path": f"projections/{case_id}.json",
                "sha256": projection_sha,
            },
            "issue_url": issue_url,
            "repo": repo,
            "request_envelope": {
                "path": request_path.relative_to(prep_root).as_posix(),
                "sha256": _sha(request_path),
            },
        }
        package_path = _write(prep_root / "packages" / f"{case_id}.json", package)
        package_refs.append(
            {
                "case_id": case_id,
                "path": package_path.relative_to(prep_root).as_posix(),
            }
        )
        production_sha = hashlib.sha256(f"production:{case_id}".encode()).hexdigest()
        packet = {"case_id": case_id, "packet_sha256": hashlib.sha256(case_id.encode()).hexdigest()}
        packet_path = _write(mapping_root / "packets" / case_id / "packet.json", packet)
        mapping_rows.append(
            {
                "case_id": case_id,
                "packet": {"path": packet_path.relative_to(mapping_root).as_posix()},
                "production_patch_sha256": production_sha,
            }
        )
        selected = [f"{case_id}:h001:{number:016x}"]
        consensus_rows.append(
            {
                "case_id": case_id,
                "consensus": {
                    "mode": "two_reviewer_agreement",
                    "selected_hunk_ids": selected,
                    "verdict": "approved",
                },
                "packet_sha256": packet["packet_sha256"],
            }
        )
        is_sympy = number in {16, 17}
        is_network = number == 14
        capability_rows.append(
            {
                "case_id": case_id,
                "evaluator_public_commitment_sha256": hashlib.sha256(
                    f"evaluator:{case_id}".encode()
                ).hexdigest(),
                "evidence": {
                    "case_id": case_id,
                    "gold_smoke": {
                        "case_classification": (
                            "infrastructure_failure" if is_network else "semantic_valid"
                        ),
                        "case_reason": (
                            "network_dependency" if is_network else "fails_on_base_passes_on_fixed"
                        ),
                    },
                    "hidden_inputs": {"production_patch_sha256": production_sha},
                    "runtime": {
                        "base_sha": base_sha,
                        "case_id": case_id,
                        "instance_id": instance_id,
                        "test_command_profile": ("sympy-bin-test-v1" if is_sympy else "pytest-v1"),
                    },
                    "runtime_manifest_sha256": MANIFEST_SHA,
                },
                "status": (
                    "runtime_attested_gold_smoke_infrastructure_failure"
                    if is_network
                    else "runtime_attested_evaluator_preflight_ready"
                ),
            }
        )

    preparation_record = {
        "packages": package_refs,
        "prepared_at": "2026-07-11T08:00:00Z",
        "request_set_sha256": "c" * 64,
        "tool": {"git_sha": TOOL_SHA},
    }
    preparation_path = _write(prep_root / "preparation.json", preparation_record)
    mapping_preparation = _write(
        mapping_root / "mapping-preparation.json",
        {"cases": mapping_rows, "prepared_at": "2026-07-11T08:10:00Z"},
    )
    mapping_consensus = _write(
        root / "mapping-consensus.json",
        {"cases": consensus_rows, "sealed_at": "2026-07-11T08:20:00Z"},
    )
    capability_index = _write(
        root / "capability-index.json",
        {
            "cases": capability_rows,
            "prepared_at": "2026-07-11T08:30:00Z",
            "tool_git_sha": TOOL_SHA,
        },
    )
    chronology = _write(root / "chronology.json", {"captured_at": "2026-07-11T08:05:00Z"})
    cohort = _write(root / "cohort.json", {"placeholder": True})
    hidden = _write(root / "hidden.json", {"placeholder": True})
    runtime = _write(root / "runtime.json", {"placeholder": True})
    gold = _write(root / "gold.json", {"placeholder": True})
    issue_responses = root / "issue-responses"
    issue_responses.mkdir()
    plan = {"cases": plan_cases, "cohort_plan_sha256": "d" * 64}

    monkeypatch.setattr(exact, "load_v02_leak_audited_cohort_plan", lambda _path: plan)
    monkeypatch.setattr(
        exact,
        "verify_v02_cases",
        lambda _path: SimpleNamespace(
            root=prep_root,
            receipt_path=preparation_path,
            receipt_sha256=_sha(preparation_path),
            case_count=20,
            provider_calls=0,
        ),
    )
    monkeypatch.setattr(
        exact,
        "verify_v02_chronology_evidence",
        lambda *_args, **_kwargs: SimpleNamespace(
            path=chronology,
            sha256=_sha(chronology),
            case_count=20,
            issue_precedes_fix_count=20,
            provider_calls=0,
        ),
    )
    monkeypatch.setattr(
        exact,
        "verify_v02_mapping_consensus",
        lambda *_args, **_kwargs: SimpleNamespace(
            path=mapping_consensus,
            sha256=_sha(mapping_consensus),
            case_count=20,
        ),
    )
    monkeypatch.setattr(
        exact,
        "verify_v02_exact_image_capability_index",
        lambda *_args, **_kwargs: SimpleNamespace(
            path=capability_index,
            sha256=_sha(capability_index),
            case_count=20,
            runtime_attested_count=20,
            evaluator_preflight_ready_count=19,
            infrastructure_failure_count=1,
            provider_calls=0,
        ),
    )
    return {
        "cases_preparation_path": preparation_path,
        "cohort_plan_path": cohort,
        "chronology_path": chronology,
        "hidden_extraction_receipt": hidden,
        "issue_responses_root": issue_responses,
        "mapping_preparation_path": mapping_preparation,
        "mapping_consensus_path": mapping_consensus,
        "capability_index_path": capability_index,
        "runtime_manifest_path": runtime,
        "expected_runtime_manifest_sha256": MANIFEST_SHA,
        "gold_smoke_receipt_path": gold,
        "frozen_at": "2026-07-11T09:00:00Z",
        "tool_git_sha": TOOL_SHA,
        "output_path": root / "exact-preregistration.json",
    }


def _verify_kwargs(values: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in values.items()
        if key not in {"frozen_at", "tool_git_sha", "output_path"}
    }


def test_exact_preregistration_round_trip_schema_and_profiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    verified = exact.prepare_v02_exact_preregistration(**values)
    assert verified.case_count == 20
    record = json.loads(verified.path.read_text())
    assert record["claims"] == {
        "evaluator_preflight_ready_count": 19,
        "infrastructure_failure_count": 1,
        "mapping_approved_count": 20,
        "model_or_provider_invoked": False,
        "provider_calls": 0,
    }
    assert record["cases"][13]["evaluator_status"].endswith("infrastructure_failure")
    assert [record["cases"][index]["candidate_profile"] for index in (15, 16)] == [
        "sympy-native-v1",
        "sympy-native-v1",
    ]
    assert [row["case_id"] for row in record["cases"]] == [
        f"rk-v0.2-{number:03d}" for number in range(1, 21)
    ]
    schema = json.loads(Path("schemas/benchmark-v02-exact-preregistration.schema.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(record)
    assert (
        exact.verify_v02_exact_preregistration(verified.path, **_verify_kwargs(values)).sha256
        == verified.sha256
    )


def test_verifier_rederives_evidence_after_self_hash_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    verified = exact.prepare_v02_exact_preregistration(**values)
    record = json.loads(verified.path.read_text())
    record["cases"][0]["rendered_input_sha256"] = "0" * 64
    record["cases"][0]["case_commitment_sha256"] = exact._json_sha256(
        {k: v for k, v in record["cases"][0].items() if k != "case_commitment_sha256"}
    )
    record["case_set_sha256"] = exact._json_sha256(
        {
            "algorithm": "reproassert-v02-exact-preregistered-case-set-v1",
            "case_commitments": [row["case_commitment_sha256"] for row in record["cases"]],
        }
    )
    record["preregistration_sha256"] = exact._self_hash(record)
    verified.path.write_bytes(_canonical(record))
    with pytest.raises(PolicyRejection, match="differs from freshly verified evidence"):
        exact.verify_v02_exact_preregistration(verified.path, **_verify_kwargs(values))


def test_preregistration_rejects_unapproved_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    path = values["mapping_consensus_path"]
    record = json.loads(path.read_text())
    record["cases"][4]["consensus"] = {
        "mode": "two_reviewer_agreement",
        "selected_hunk_ids": [],
        "verdict": "rejected",
    }
    path.write_bytes(_canonical(record))
    with pytest.raises(PolicyRejection, match="lacks an approved"):
        exact.prepare_v02_exact_preregistration(**values)


@pytest.mark.parametrize("mutation", ["case_swap", "case014_success", "tool_sha"])
def test_preregistration_rejects_cross_bound_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    values = _fixtures(tmp_path, monkeypatch)
    if mutation == "case_swap":
        path = values["capability_index_path"]
        record = json.loads(path.read_text())
        record["cases"][0], record["cases"][1] = record["cases"][1], record["cases"][0]
        path.write_bytes(_canonical(record))
    elif mutation == "case014_success":
        path = values["capability_index_path"]
        record = json.loads(path.read_text())
        row = record["cases"][13]
        row["status"] = "runtime_attested_evaluator_preflight_ready"
        row["evidence"]["gold_smoke"] = {
            "case_classification": "semantic_valid",
            "case_reason": "fails_on_base_passes_on_fixed",
        }
        path.write_bytes(_canonical(record))
    else:
        values["tool_git_sha"] = "e" * 40
    with pytest.raises(PolicyRejection):
        exact.prepare_v02_exact_preregistration(**values)
