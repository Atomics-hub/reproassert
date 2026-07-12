from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

import reproassert.benchmark_v021_authorization as authorization_module
import reproassert.benchmark_v021_ledger as ledger_module
import reproassert.benchmark_v021_runtime_ledger as runtime_ledger_module
from reproassert.errors import PolicyRejection

APPROVAL = "Authorize the exact v0.2.1 campaign."
AUTHORIZATION_REF = "operator:benchmark-v021-2026-07-11"
OPERATOR_NONCE = "7" * 64
TOOL_SHA = "9" * 40
LINEAGE = "a" * 64
CALL_ID = "c" * 64
CASE_IDS = authorization_module.CASE_IDS
REQUEST_DIGESTS = {
    case_id: hashlib.sha256(f"request:{case_id}".encode()).hexdigest() for case_id in CASE_IDS
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[SimpleNamespace, Path, Path]:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    claim_root = tmp_path / "claim-state"
    claim_root.mkdir(mode=0o700)
    monkeypatch.setattr(ledger_module, "_claim_state_root", lambda: claim_root)
    monkeypatch.setattr(authorization_module, "_claim_state_root", lambda: claim_root)
    record: dict[str, object] = {
        "algorithm": "reproassert-v021-provider-disabled-preregistration-v1",
        "approval": {
            "authorized": False,
            "required_exact_statement": APPROVAL,
            "required_exact_statement_sha256": hashlib.sha256(APPROVAL.encode()).hexdigest(),
        },
        "benchmark_version": "0.2.1",
        "case_count": 20,
        "claims": {},
        "evidence": {
            "internal_commitments": {
                "case_request_set_sha256": hashlib.sha256(
                    _canonical(
                        {
                            "algorithm": authorization_module.LEGACY_REQUEST_SET_ALGORITHM,
                            "sha256": [REQUEST_DIGESTS[case_id] for case_id in CASE_IDS],
                        }
                    )
                ).hexdigest()
            },
            "pricing_snapshot_raw_sha256": "b" * 64,
        },
        "frozen_at": "2026-07-11T10:00:00Z",
        "lineage_commitment_sha256": LINEAGE,
        "policy": {
            "case_cap_usd": "0.25",
            "credential_fields_allowed": False,
            "execution_enabled": False,
            "model": "gpt-5.4-mini-2026-03-17",
            "overage_allowed": False,
            "pricing_effective_at": "2026-03-17T00:00:00Z",
            "pricing_snapshot_status": "exact_public_snapshot_hash_bound",
            "total_cap_usd": "5.00",
        },
        "schema_version": "1.0.0",
        "status": "execution_disabled_until_v021_runtime_migration",
        "tool_git_sha": TOOL_SHA,
    }
    record["preregistration_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
    prereg_path = root / "prereg.json"
    prereg_path.write_bytes(_canonical(record) + b"\n")
    authority = SimpleNamespace(
        path=prereg_path,
        sha256=hashlib.sha256(prereg_path.read_bytes()).hexdigest(),
        lineage_commitment_sha256=LINEAGE,
        approval_statement=APPROVAL,
        approval_statement_sha256=hashlib.sha256(APPROVAL.encode()).hexdigest(),
        case_count=20,
        provider_calls=0,
        execution_enabled=False,
    )
    monkeypatch.setattr(authorization_module, "require_v021_preregistration", lambda value: value)
    return authority, root / "ledger.jsonl", root / "authorization.json"


def _authorize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[SimpleNamespace, authorization_module.VerifiedV021ExecutionAuthorization]:
    prereg, ledger, output = _fixture(tmp_path, monkeypatch)
    statement = _statement(prereg, ledger.absolute(), AUTHORIZATION_REF, OPERATOR_NONCE)
    auth = authorization_module.prepare_v021_execution_authorization(
        preregistration=prereg,
        execution_statement=statement,
        authorization_ref=AUTHORIZATION_REF,
        operator_nonce=OPERATOR_NONCE,
        case_ids=list(authorization_module.CASE_IDS),
        request_envelope_sha256_by_case=REQUEST_DIGESTS,
        ledger_path=ledger.absolute(),
        authorized_at="2026-07-11T10:01:00Z",
        output_path=output,
    )
    return prereg, auth


def _statement(
    prereg: SimpleNamespace,
    ledger: Path,
    authorization_ref: str,
    operator_nonce: str,
    *,
    authorized_at: str = "2026-07-11T10:01:00Z",
) -> str:
    rows = [
        {"case_id": case_id, "request_envelope_sha256": REQUEST_DIGESTS[case_id]}
        for case_id in CASE_IDS
    ]
    request_set = hashlib.sha256(
        _canonical({"algorithm": authorization_module.REQUEST_SET_ALGORITHM, "requests": rows})
    ).hexdigest()
    prereg_sha = str(prereg.sha256)
    ledger = ledger.resolve(strict=False)
    ledger_identity = hashlib.sha256(
        _canonical({"absolute_path": str(ledger), "preregistration_sha256": prereg_sha})
    ).hexdigest()
    return authorization_module.required_v021_execution_statement(
        preregistration_raw_sha256=prereg_sha,
        request_set_sha256=request_set,
        ledger_absolute_path=ledger,
        ledger_identity_sha256=ledger_identity,
        model=authorization_module.MODEL,
        total_cap_usd=authorization_module.TOTAL_CAP_USD,
        per_case_cap_usd=authorization_module.PER_CASE_CAP_USD,
        overage_allowed=False,
        authorized_at=authorized_at,
        authorization_ref=authorization_ref,
        operator_nonce=operator_nonce,
    )


def test_authorization_binds_exact_prereg_policy_and_absolute_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prereg, auth = _authorize(tmp_path, monkeypatch)
    assert auth.case_ids == authorization_module.CASE_IDS
    assert auth.preregistration_request_set_sha256 != auth.request_set_sha256
    assert dict(auth.request_sha256_by_case) == REQUEST_DIGESTS
    assert auth.lineage_commitment_sha256 == LINEAGE
    assert auth.total_cap_usd == "5.00"
    assert auth.per_case_cap_usd == "0.25"
    assert auth.authorization_ref == AUTHORIZATION_REF
    assert auth.operator_nonce == OPERATOR_NONCE
    assert hashlib.sha256(auth.execution_statement.encode()).hexdigest() == (
        auth.execution_statement_sha256
    )
    assert auth.ledger_path.is_absolute()
    assert (
        authorization_module.verify_v021_execution_authorization(
            auth.path, preregistration=prereg, expected_ledger_path=auth.ledger_path
        ).sha256
        == auth.sha256
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("execution_statement", APPROVAL),
        ("case_ids", list(reversed(authorization_module.CASE_IDS))),
        (
            "request_envelope_sha256_by_case",
            {**REQUEST_DIGESTS, CASE_IDS[0]: "e" * 64},
        ),
        ("authorized_at", "2026-07-11T09:59:00Z"),
    ],
)
def test_authorization_rejects_statement_case_request_and_chronology_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    prereg, ledger, output = _fixture(tmp_path, monkeypatch)
    statement = _statement(prereg, ledger.absolute(), AUTHORIZATION_REF, OPERATOR_NONCE)
    kwargs: dict[str, object] = {
        "preregistration": prereg,
        "execution_statement": statement,
        "authorization_ref": AUTHORIZATION_REF,
        "operator_nonce": OPERATOR_NONCE,
        "case_ids": list(authorization_module.CASE_IDS),
        "request_envelope_sha256_by_case": REQUEST_DIGESTS,
        "ledger_path": ledger.absolute(),
        "authorized_at": "2026-07-11T10:01:00Z",
        "output_path": output,
    }
    kwargs[field] = value
    with pytest.raises(PolicyRejection):
        authorization_module.prepare_v021_execution_authorization(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("authorization_ref", "operator_nonce"),
    [
        ("x", OPERATOR_NONCE),
        ("operator\nref", OPERATOR_NONCE),
        (AUTHORIZATION_REF, "not-a-64-hex-nonce"),
        (AUTHORIZATION_REF, "A" * 64),
    ],
)
def test_authorization_rejects_unbounded_ref_and_invalid_nonce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authorization_ref: str,
    operator_nonce: str,
) -> None:
    prereg, ledger, output = _fixture(tmp_path, monkeypatch)
    with pytest.raises(PolicyRejection):
        authorization_module.prepare_v021_execution_authorization(
            preregistration=prereg,
            execution_statement=APPROVAL,
            authorization_ref=authorization_ref,
            operator_nonce=operator_nonce,
            case_ids=list(CASE_IDS),
            request_envelope_sha256_by_case=REQUEST_DIGESTS,
            ledger_path=ledger.absolute(),
            authorized_at="2026-07-11T10:01:00Z",
            output_path=output,
        )


def test_global_issuance_claim_blocks_second_ledger_and_deleted_local_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prereg, auth = _authorize(tmp_path, monkeypatch)
    second_ledger = auth.ledger_path.with_name("second-ledger.jsonl")
    second_output = auth.path.with_name("second-authorization.json")
    second_ref = "operator:second-mint"
    second_nonce = "8" * 64
    second_statement = _statement(prereg, second_ledger, second_ref, second_nonce)
    auth.path.unlink()
    with pytest.raises(PolicyRejection, match="already has an issuance claim"):
        authorization_module.prepare_v021_execution_authorization(
            preregistration=prereg,
            execution_statement=second_statement,
            authorization_ref=second_ref,
            operator_nonce=second_nonce,
            case_ids=list(CASE_IDS),
            request_envelope_sha256_by_case=REQUEST_DIGESTS,
            ledger_path=second_ledger,
            authorized_at="2026-07-11T10:01:00Z",
            output_path=second_output,
        )


def test_verification_requires_matching_claim_without_recreating_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prereg, auth = _authorize(tmp_path, monkeypatch)
    record = json.loads(auth.path.read_bytes())
    claim = authorization_module._claim_path(record)
    claim.unlink()
    with pytest.raises(PolicyRejection, match="could not be read safely"):
        authorization_module.verify_v021_execution_authorization(
            auth.path, preregistration=prereg, expected_ledger_path=auth.ledger_path
        )
    assert not claim.exists()


def test_prepare_failure_after_claim_remains_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prereg, ledger, output = _fixture(tmp_path, monkeypatch)
    statement = _statement(prereg, ledger.absolute(), AUTHORIZATION_REF, OPERATOR_NONCE)
    original_write = authorization_module.write_bytes_exclusive
    writes = 0

    def fail_authorization_write(path: Path, content: bytes) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("simulated authorization write failure")
        original_write(path, content)

    monkeypatch.setattr(authorization_module, "write_bytes_exclusive", fail_authorization_write)
    kwargs = {
        "preregistration": prereg,
        "execution_statement": statement,
        "authorization_ref": AUTHORIZATION_REF,
        "operator_nonce": OPERATOR_NONCE,
        "case_ids": list(CASE_IDS),
        "request_envelope_sha256_by_case": REQUEST_DIGESTS,
        "ledger_path": ledger.absolute(),
        "authorized_at": "2026-07-11T10:01:00Z",
        "output_path": output,
    }
    with pytest.raises(OSError, match="simulated authorization write failure"):
        authorization_module.prepare_v021_execution_authorization(**kwargs)  # type: ignore[arg-type]
    monkeypatch.setattr(authorization_module, "write_bytes_exclusive", original_write)
    with pytest.raises(PolicyRejection, match="already has an issuance claim"):
        authorization_module.prepare_v021_execution_authorization(**kwargs)  # type: ignore[arg-type]


def test_verification_rejects_tampered_global_issuance_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prereg, auth = _authorize(tmp_path, monkeypatch)
    record = json.loads(auth.path.read_bytes())
    claim = authorization_module._claim_path(record)
    claim_record = json.loads(claim.read_bytes())
    claim_record["operator_nonce"] = "6" * 64
    claim_record["claim_sha256"] = authorization_module._self_hash_named(
        claim_record, "claim_sha256"
    )
    claim.write_bytes(_canonical(claim_record) + b"\n")
    with pytest.raises(PolicyRejection, match="claim does not match"):
        authorization_module.verify_v021_execution_authorization(
            auth.path, preregistration=prereg, expected_ledger_path=auth.ledger_path
        )


@pytest.mark.parametrize("field", ["authorization_ref", "operator_nonce", "execution_statement"])
def test_authorization_operator_tamper_fails_even_with_recomputed_self_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    prereg, auth = _authorize(tmp_path, monkeypatch)
    record = json.loads(auth.path.read_bytes())
    operator = record["authorization"]
    assert isinstance(operator, dict)
    operator[field] = "6" * 64 if field == "operator_nonce" else f"tampered-{field}"
    if field == "execution_statement":
        operator["execution_statement_sha256"] = hashlib.sha256(
            str(operator[field]).encode()
        ).hexdigest()
    record["authorization_sha256"] = authorization_module._self_hash(record)
    auth.path.write_bytes(_canonical(record) + b"\n")
    with pytest.raises(PolicyRejection):
        authorization_module.verify_v021_execution_authorization(
            auth.path, preregistration=prereg, expected_ledger_path=auth.ledger_path
        )


def test_forged_authorities_and_tampered_preregistration_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(PolicyRejection):
        authorization_module.require_v021_execution_authorization(SimpleNamespace())
    prereg, auth = _authorize(tmp_path, monkeypatch)
    prereg.path.write_bytes(prereg.path.read_bytes().replace(b'"5.00"', b'"6.00"'))
    with pytest.raises(PolicyRejection, match="changed after verification"):
        authorization_module.verify_v021_execution_authorization(
            auth.path, preregistration=prereg, expected_ledger_path=auth.ledger_path
        )


def test_ledger_claim_reserve_response_result_and_idempotent_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, auth = _authorize(tmp_path, monkeypatch)
    claimed = ledger_module.claim_v021_spend_ledger(
        authorization=auth, claimed_at="2026-07-11T10:02:00Z"
    )
    assert claimed.status == "ready"
    reservation = ledger_module.reserve_v021_case(
        authorization=auth,
        case_id=auth.case_ids[0],
        request_sha256=REQUEST_DIGESTS[auth.case_ids[0]],
        call_id=CALL_ID,
        reserved_at="2026-07-11T10:03:00Z",
    )
    halted = ledger_module.verify_v021_spend_ledger(auth.ledger_path, authorization=auth)
    assert halted.status == "unknown_spend_halt"
    recovered = ledger_module.recover_v021_case_reservation(
        authorization=auth,
        case_id=auth.case_ids[0],
        request_sha256=REQUEST_DIGESTS[auth.case_ids[0]],
        call_id=CALL_ID,
        durable_response_sha256="2" * 64,
    )
    assert recovered.reservation_event_sha256 == reservation.reservation_event_sha256
    response = ledger_module.record_v021_provider_response(
        authorization=auth,
        reservation=recovered,
        response_sha256="2" * 64,
        actual_cost_usd="0.100000",
        recorded_at="2026-07-11T10:04:00Z",
    )
    assert response.status == "ready"
    assert response.actual_cost_usd == "0.100000"
    again = ledger_module.record_v021_provider_response(
        authorization=auth,
        reservation=recovered,
        response_sha256="2" * 64,
        actual_cost_usd="0.100000",
        recorded_at="2026-07-11T10:04:30Z",
    )
    assert again.sha256 == response.sha256
    complete = ledger_module.record_v021_case_result(
        authorization=auth,
        reservation=recovered,
        response_sha256="2" * 64,
        result_sha256="3" * 64,
        recorded_at="2026-07-11T10:05:00Z",
    )
    assert complete.case_states[auth.case_ids[0]]["state"] == "completed"


def test_unknown_spend_never_retries_and_blocks_second_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, auth = _authorize(tmp_path, monkeypatch)
    ledger_module.claim_v021_spend_ledger(authorization=auth, claimed_at="2026-07-11T10:02:00Z")
    ledger_module.reserve_v021_case(
        authorization=auth,
        case_id=auth.case_ids[0],
        request_sha256=REQUEST_DIGESTS[auth.case_ids[0]],
        call_id=CALL_ID,
        reserved_at="2026-07-11T10:03:00Z",
    )
    with pytest.raises(PolicyRejection, match="never retry"):
        ledger_module.recover_v021_case_reservation(
            authorization=auth,
            case_id=auth.case_ids[0],
            request_sha256=REQUEST_DIGESTS[auth.case_ids[0]],
            call_id=CALL_ID,
            durable_response_sha256=None,
        )
    with pytest.raises(PolicyRejection, match="unknown_spend_halt"):
        ledger_module.reserve_v021_case(
            authorization=auth,
            case_id=auth.case_ids[1],
            request_sha256=REQUEST_DIGESTS[auth.case_ids[1]],
            call_id="d" * 64,
            reserved_at="2026-07-11T10:04:00Z",
        )


def test_concrete_runtime_port_drives_irreversible_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, auth = _authorize(tmp_path, monkeypatch)
    ledger_module.claim_v021_spend_ledger(authorization=auth, claimed_at="2026-07-11T10:02:00Z")
    port = runtime_ledger_module.V021SpendLedgerPort(auth)
    case_id = auth.case_ids[0]
    request_sha = REQUEST_DIGESTS[case_id]
    call_id = runtime_ledger_module._call_id(auth.sha256, case_id, request_sha)
    assert port.state(case_id, request_sha).status == "unreserved"
    port.reserve(case_id, request_sha, call_id)
    assert port.state(case_id, request_sha).status == "reserved"
    port.record_unknown_spend_halt(case_id, request_sha, call_id)
    port.record_response(case_id, request_sha, "2" * 64, 100_000)
    assert port.state(case_id, request_sha).status == "response_recorded"
    port.record_result(case_id, request_sha, "2" * 64, "3" * 64)
    assert port.state(case_id, request_sha).status == "result_recorded"


def test_second_ledger_double_reservation_and_cross_case_bindings_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, auth = _authorize(tmp_path, monkeypatch)
    ledger_module.claim_v021_spend_ledger(authorization=auth, claimed_at="2026-07-11T10:02:00Z")
    with pytest.raises(PolicyRejection, match="already claimed"):
        ledger_module.claim_v021_spend_ledger(authorization=auth, claimed_at="2026-07-11T10:02:01Z")
    reservation = ledger_module.reserve_v021_case(
        authorization=auth,
        case_id=auth.case_ids[0],
        request_sha256=REQUEST_DIGESTS[auth.case_ids[0]],
        call_id=CALL_ID,
        reserved_at="2026-07-11T10:03:00Z",
    )
    with pytest.raises(PolicyRejection):
        ledger_module.reserve_v021_case(
            authorization=auth,
            case_id=auth.case_ids[0],
            request_sha256=REQUEST_DIGESTS[auth.case_ids[0]],
            call_id=CALL_ID,
            reserved_at="2026-07-11T10:03:01Z",
        )
    forged = object.__new__(ledger_module.V021CaseReservation)
    for name, value in reservation.__dict__.items():
        object.__setattr__(forged, name, value)
    object.__setattr__(forged, "case_id", auth.case_ids[1])
    with pytest.raises(PolicyRejection):
        ledger_module.record_v021_provider_response(
            authorization=auth,
            reservation=forged,
            response_sha256="2" * 64,
            actual_cost_usd="0.100000",
            recorded_at="2026-07-11T10:04:00Z",
        )


def test_global_claim_survives_deleted_campaign_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, auth = _authorize(tmp_path, monkeypatch)
    ledger_module.claim_v021_spend_ledger(authorization=auth, claimed_at="2026-07-11T10:02:00Z")
    claim = ledger_module._claim_path(auth)
    assert claim.parent != auth.ledger_path.parent
    auth.ledger_path.unlink()
    with pytest.raises(PolicyRejection, match="already claimed"):
        ledger_module.claim_v021_spend_ledger(authorization=auth, claimed_at="2026-07-11T10:03:00Z")


def test_locked_ledger_rejects_path_inode_swap_before_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, auth = _authorize(tmp_path, monkeypatch)
    ledger_module.claim_v021_spend_ledger(authorization=auth, claimed_at="2026-07-11T10:02:00Z")
    original_verify = ledger_module.verify_v021_spend_ledger
    original_path = auth.ledger_path.with_name("old-ledger.jsonl")
    swapped = False

    def swap_then_verify(path: Path, *, authorization: object):
        nonlocal swapped
        if not swapped:
            swapped = True
            raw = auth.ledger_path.read_bytes()
            os.replace(auth.ledger_path, original_path)
            auth.ledger_path.write_bytes(raw)
            auth.ledger_path.chmod(0o600)
        return original_verify(path, authorization=authorization)  # type: ignore[arg-type]

    monkeypatch.setattr(ledger_module, "verify_v021_spend_ledger", swap_then_verify)
    with pytest.raises(PolicyRejection, match="inode changed"):
        ledger_module.reserve_v021_case(
            authorization=auth,
            case_id=auth.case_ids[0],
            request_sha256=REQUEST_DIGESTS[auth.case_ids[0]],
            call_id=CALL_ID,
            reserved_at="2026-07-11T10:03:00Z",
        )
    state = original_verify(auth.ledger_path, authorization=auth).case_states[auth.case_ids[0]]
    assert state["state"] == "available"


@pytest.mark.parametrize("corruption", ["truncate", "splice", "mutate"])
def test_ledger_rejects_truncation_splice_and_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    _, auth = _authorize(tmp_path, monkeypatch)
    ledger_module.claim_v021_spend_ledger(authorization=auth, claimed_at="2026-07-11T10:02:00Z")
    original = auth.ledger_path.read_bytes()
    if corruption == "truncate":
        auth.ledger_path.write_bytes(original[:-1])
    elif corruption == "splice":
        auth.ledger_path.write_bytes(original + original)
    else:
        auth.ledger_path.write_bytes(original.replace(b"ledger_claimed", b"ledger_claimeD"))
    with pytest.raises(PolicyRejection):
        ledger_module.verify_v021_spend_ledger(auth.ledger_path, authorization=auth)


def test_public_and_packaged_schemas_match_and_validate_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, auth = _authorize(tmp_path, monkeypatch)
    ledger_module.claim_v021_spend_ledger(authorization=auth, claimed_at="2026-07-11T10:02:00Z")
    for name, value in [
        ("benchmark-v021-execution-authorization.schema.json", json.loads(auth.path.read_bytes())),
        (
            "benchmark-v021-spend-ledger-event.schema.json",
            json.loads(auth.ledger_path.read_bytes().splitlines()[0]),
        ),
    ]:
        public = Path("schemas") / name
        packaged = Path("src/reproassert/schemas") / name
        assert public.read_bytes() == packaged.read_bytes()
        Draft202012Validator(json.loads(public.read_bytes())).validate(value)


def test_checked_in_public_spend_ledger_is_complete_and_tamper_evident(tmp_path: Path) -> None:
    source = Path("benchmarks/v0.2-results/spend-ledger.jsonl")
    checked = ledger_module.inspect_v021_public_spend_ledger(source)

    assert checked.provider_calls == 20
    assert checked.completed_cases == 20
    assert checked.unknown_spend_cases == 0
    assert checked.total_cost_usd == "0.688111"
    assert checked.minimum_case_cost_usd == "0.022471"
    assert checked.maximum_case_cost_usd == "0.051351"
    assert checked.sha256 == "b83854480b3caad05242a1924f032a92ad873cc75fbbb56009362680da6bc770"
    assert checked.head_event_sha256 == (
        "22e79e849c85717777719b1d35fd24622f4191084a1bc01247a5c6d33a31266f"
    )

    tampered = tmp_path / "spend-ledger.jsonl"
    tampered.write_bytes(source.read_bytes().replace(b'"0.040239"', b'"0.040238"', 1))
    with pytest.raises(PolicyRejection, match="hash chain"):
        ledger_module.inspect_v021_public_spend_ledger(tampered)
