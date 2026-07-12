from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from reproassert import benchmark_v021_authorization as authorization
from reproassert import benchmark_v021_automated_preregistration as automated
from reproassert.benchmark_v021_preregistration_authority import (
    require_v021_execution_preregistration,
)
from reproassert.errors import PolicyRejection


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _automated_preregistration(tmp_path: Path) -> automated.VerifiedV021AutomatedPreregistration:
    requests = {
        case_id: hashlib.sha256(case_id.encode()).hexdigest() for case_id in authorization.CASE_IDS
    }
    legacy_set = hashlib.sha256(
        _canonical(
            {
                "algorithm": authorization.LEGACY_REQUEST_SET_ALGORITHM,
                "sha256": list(requests.values()),
            }
        )
    ).hexdigest()
    statement = "automated authority fixture"
    record: dict[str, object] = {
        "algorithm": automated.ALGORITHM,
        "approval": {
            "authorized": False,
            "required_exact_statement": statement,
            "required_exact_statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "benchmark_version": "0.2.1",
        "case_count": 20,
        "claims": {
            "automated_oracle_validated": True,
            "human_reviewed": False,
            "maintainer_validated": False,
        },
        "evidence": {
            "internal_commitments": {"case_request_set_sha256": legacy_set},
            "pricing_snapshot_commitment_sha256": "b" * 64,
        },
        "frozen_at": "2026-07-12T00:00:00Z",
        "lineage_commitment_sha256": "c" * 64,
        "policy": {
            "case_cap_usd": "0.25",
            "credential_fields_allowed": False,
            "execution_enabled": False,
            "model": authorization.MODEL,
            "overage_allowed": False,
            "pricing_effective_at": "2026-03-17T00:00:00Z",
            "pricing_snapshot_status": "exact_public_snapshot_hash_bound",
            "total_cap_usd": "5.00",
        },
        "schema_version": "1.0.0",
        "status": automated.STATUS,
        "tool_git_sha": "d" * 40,
    }
    record["preregistration_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
    raw = _canonical(record) + b"\n"
    path = tmp_path / "automated-preregistration.json"
    path.write_bytes(raw)
    value = object.__new__(automated.VerifiedV021AutomatedPreregistration)
    for name, item in {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "lineage_commitment_sha256": "c" * 64,
        "approval_statement": statement,
        "approval_statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        "case_count": 20,
        "dependency_ready_count": 20,
        "provider_calls": 0,
        "execution_enabled": False,
        "human_reviewed": False,
        "maintainer_validated": False,
        "_issuer": automated._ISSUER,
    }.items():
        object.__setattr__(value, name, item)
    return value


def test_automated_preregistration_can_issue_exact_capped_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prereg = _automated_preregistration(tmp_path)
    claim_root = tmp_path / "claims"
    claim_root.mkdir(mode=0o700)
    monkeypatch.setattr(authorization, "_claim_state_root", lambda: claim_root)
    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir(mode=0o700)
    ledger = ledger_root / "spend.jsonl"
    requests = {
        case_id: hashlib.sha256(case_id.encode()).hexdigest() for case_id in authorization.CASE_IDS
    }
    request_rows = [
        {"case_id": case_id, "request_envelope_sha256": digest}
        for case_id, digest in requests.items()
    ]
    request_set = hashlib.sha256(
        _canonical({"algorithm": authorization.REQUEST_SET_ALGORITHM, "requests": request_rows})
    ).hexdigest()
    ledger_identity = hashlib.sha256(
        _canonical(
            {"absolute_path": str(ledger.resolve()), "preregistration_sha256": prereg.sha256}
        )
    ).hexdigest()
    nonce = "e" * 64
    authorized_at = "2026-07-12T00:00:01Z"
    reference = "tom-approved-five-dollar-cap"
    statement = authorization.required_v021_execution_statement(
        preregistration_raw_sha256=prereg.sha256,
        request_set_sha256=request_set,
        ledger_absolute_path=ledger,
        ledger_identity_sha256=ledger_identity,
        model=authorization.MODEL,
        total_cap_usd="5.00",
        per_case_cap_usd="0.25",
        overage_allowed=False,
        authorized_at=authorized_at,
        authorization_ref=reference,
        operator_nonce=nonce,
    )

    issued = authorization.prepare_v021_execution_authorization(
        preregistration=prereg,
        execution_statement=statement,
        authorization_ref=reference,
        operator_nonce=nonce,
        case_ids=list(authorization.CASE_IDS),
        request_envelope_sha256_by_case=requests,
        ledger_path=ledger,
        authorized_at=authorized_at,
        output_path=tmp_path / "authorization.json",
    )

    assert issued.preregistration_sha256 == prereg.sha256
    assert issued.total_cap_usd == "5.00"
    assert issued.per_case_cap_usd == "0.25"


def test_structural_lookalike_cannot_cross_the_authority_bridge() -> None:
    with pytest.raises(PolicyRejection, match="verifier-issued"):
        require_v021_execution_preregistration(
            SimpleNamespace(execution_enabled=False, provider_calls=0)
        )
