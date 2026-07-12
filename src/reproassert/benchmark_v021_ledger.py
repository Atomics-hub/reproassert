"""Irreversible, provider-neutral spend ledger for ReproAssert v0.2.1."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pwd
import re
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO, cast

from reproassert.benchmark_v021_authorization import (
    PER_CASE_CAP_USD,
    TOTAL_CAP_USD,
    VerifiedV021ExecutionAuthorization,
    require_v021_execution_authorization,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

ALGORITHM = "reproassert-v021-spend-ledger-event-v1"
CLAIM_ALGORITHM = "reproassert-v021-spend-ledger-claim-v1"
SCHEMA_VERSION = "1.0.0"
MAX_BYTES = 8 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TIME = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_ISSUER = object()
_RESERVATION_ISSUER = object()


@dataclass(frozen=True, init=False)
class V021CaseReservation:
    authorization_sha256: str
    ledger_identity_sha256: str
    case_id: str
    request_sha256: str
    call_id: str
    reservation_event_sha256: str
    durable_response_sha256: str | None
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("V021CaseReservation is ledger-issued only")


@dataclass(frozen=True, init=False)
class VerifiedV021SpendLedger:
    path: Path
    sha256: str
    authorization_sha256: str
    preregistration_sha256: str
    lineage_commitment_sha256: str
    request_set_sha256: str
    ledger_identity_sha256: str
    events: tuple[Mapping[str, object], ...]
    head_event_sha256: str
    case_states: Mapping[str, Mapping[str, object]]
    reserved_case_ids: tuple[str, ...]
    completed_case_ids: tuple[str, ...]
    unknown_spend_case_ids: tuple[str, ...]
    actual_cost_usd: str
    status: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV021SpendLedger is verifier-issued only")


def claim_v021_spend_ledger(
    *, authorization: VerifiedV021ExecutionAuthorization, claimed_at: str
) -> VerifiedV021SpendLedger:
    auth = require_v021_execution_authorization(authorization)
    ledger = auth.ledger_path
    require_private_directory(ledger.parent)
    claim = _claim_path(auth)
    if ledger.exists() or ledger.is_symlink() or claim.exists() or claim.is_symlink():
        raise _reject("Authorization or ledger identity was already claimed.")
    timestamp = _timestamp(claimed_at)
    claim_record = {
        "algorithm": CLAIM_ALGORITHM,
        "authorization_sha256": auth.sha256,
        "claimed_at": timestamp,
        "ledger_absolute_path": str(ledger),
        "ledger_identity_sha256": auth.ledger_identity_sha256,
        "schema_version": SCHEMA_VERSION,
    }
    claim_record["claim_sha256"] = _hash_without(claim_record, "claim_sha256")
    write_bytes_exclusive(claim, _canonical(claim_record) + b"\n")
    try:
        event = _event(
            auth,
            sequence=1,
            previous=None,
            event_type="ledger_claimed",
            case_id=None,
            recorded_at=timestamp,
            payload={"claim_sha256": claim_record["claim_sha256"]},
        )
        write_bytes_exclusive(ledger, _canonical(event) + b"\n")
    except Exception:
        with suppress(OSError):
            claim.unlink()
        raise
    return verify_v021_spend_ledger(ledger, authorization=auth)


def verify_v021_spend_ledger(
    path: Path, *, authorization: VerifiedV021ExecutionAuthorization
) -> VerifiedV021SpendLedger:
    auth = require_v021_execution_authorization(authorization)
    ledger = Path(path)
    if ledger != auth.ledger_path:
        raise _reject("Ledger path differs from the authorization-bound absolute identity.")
    claim_record = _load_claim(_claim_path(auth), auth)
    raw = _read(ledger, MAX_BYTES, "spend ledger")
    events = _decode_events(raw)
    if not events:
        raise _reject("Spend ledger is empty.")
    previous: str | None = None
    previous_time = _time_value(auth.authorized_at)
    for sequence, event in enumerate(events, 1):
        if set(event) != {
            "algorithm",
            "authorization_sha256",
            "benchmark_version",
            "case_id",
            "event_sha256",
            "event_type",
            "ledger_identity_sha256",
            "lineage_commitment_sha256",
            "payload",
            "preregistration_sha256",
            "recorded_at",
            "request_set_sha256",
            "schema_version",
            "sequence",
        }:
            raise _reject("Ledger event fields are invalid.")
        event_type = event.get("event_type")
        payload = event.get("payload")
        if not isinstance(payload, dict) or set(payload) != _payload_fields(event_type):
            raise _reject("Ledger event payload fields are invalid.")
        if (
            event.get("algorithm") != ALGORITHM
            or event.get("schema_version") != SCHEMA_VERSION
            or event.get("benchmark_version") != "0.2.1"
            or event.get("sequence") != sequence
            or event.get("event_sha256") != _hash_without(event, "event_sha256")
            or cast(dict[str, object], event["payload"]).get("previous_event_sha256") != previous
            or event.get("authorization_sha256") != auth.sha256
            or event.get("preregistration_sha256") != auth.preregistration_sha256
            or event.get("lineage_commitment_sha256") != auth.lineage_commitment_sha256
            or event.get("request_set_sha256") != auth.request_set_sha256
            or event.get("ledger_identity_sha256") != auth.ledger_identity_sha256
        ):
            raise _reject("Ledger hash chain or campaign binding is invalid.")
        event_time = _time_value(_timestamp(event.get("recorded_at")))
        if event_time < previous_time:
            raise _reject("Ledger event chronology is invalid.")
        previous_time = event_time
        previous = cast(str, event["event_sha256"])
    first = events[0]
    first_payload = cast(dict[str, object], first["payload"])
    if (
        first.get("event_type") != "ledger_claimed"
        or first.get("case_id") is not None
        or first_payload.get("claim_sha256") != claim_record.get("claim_sha256")
    ):
        raise _reject("Ledger does not begin with its exclusive authorization claim.")
    states, actual_cost = _derive_states(events, auth)
    unknown = tuple(
        case for case in auth.case_ids if states[case]["state"] == "reserved_unknown_spend"
    )
    completed = tuple(case for case in auth.case_ids if states[case]["state"] == "completed")
    reserved = tuple(case for case in auth.case_ids if states[case]["state"] != "available")
    status = "unknown_spend_halt" if unknown else ("complete" if len(completed) == 20 else "ready")
    issued = object.__new__(VerifiedV021SpendLedger)
    frozen_events = tuple(MappingProxyType(event) for event in events)
    frozen_states = MappingProxyType(
        {case: MappingProxyType(dict(state)) for case, state in states.items()}
    )
    values: dict[str, object] = {
        "path": ledger,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "authorization_sha256": auth.sha256,
        "preregistration_sha256": auth.preregistration_sha256,
        "lineage_commitment_sha256": auth.lineage_commitment_sha256,
        "request_set_sha256": auth.request_set_sha256,
        "ledger_identity_sha256": auth.ledger_identity_sha256,
        "events": frozen_events,
        "head_event_sha256": previous,
        "case_states": frozen_states,
        "reserved_case_ids": reserved,
        "completed_case_ids": completed,
        "unknown_spend_case_ids": unknown,
        "actual_cost_usd": _money(actual_cost),
        "status": status,
        "_issuer": _ISSUER,
    }
    for name, value in values.items():
        object.__setattr__(issued, name, value)
    return issued


def _payload_fields(event_type: object) -> set[str]:
    common = {"previous_event_sha256"}
    if event_type == "ledger_claimed":
        return common | {"claim_sha256"}
    if event_type == "case_reserved":
        return common | {"call_id", "maximum_cost_usd", "request_sha256"}
    if event_type == "provider_response_durable":
        return common | {
            "actual_cost_usd",
            "call_id",
            "request_sha256",
            "response_sha256",
            "reservation_event_sha256",
        }
    if event_type == "case_completed":
        return common | {
            "call_id",
            "request_sha256",
            "response_sha256",
            "result_sha256",
            "reservation_event_sha256",
        }
    return set()


def reserve_v021_case(
    *,
    authorization: VerifiedV021ExecutionAuthorization,
    case_id: str,
    request_sha256: str,
    call_id: str,
    reserved_at: str,
) -> V021CaseReservation:
    auth = require_v021_execution_authorization(authorization)
    _require_case(auth, case_id)
    request = _sha(request_sha256)
    call = _sha(call_id)
    if request != auth.request_sha256_by_case[case_id]:
        raise _reject("Case request differs from the authorization-bound request envelope.")
    with _locked(auth) as stream:
        snapshot = verify_v021_spend_ledger(auth.ledger_path, authorization=auth)
        _assert_stream_matches(stream, auth.ledger_path, snapshot.sha256)
        if snapshot.unknown_spend_case_ids:
            raise _reject("unknown_spend_halt: an unresolved reservation forbids all new spend.")
        if snapshot.case_states[case_id]["state"] != "available":
            raise _reject("Case already has an irreversible spend reservation.")
        event = _append_locked(
            stream,
            auth,
            snapshot,
            "case_reserved",
            case_id,
            _timestamp(reserved_at),
            {
                "call_id": call,
                "maximum_cost_usd": PER_CASE_CAP_USD,
                "request_sha256": request,
            },
        )
    return _reservation(auth, case_id, request, call, cast(str, event["event_sha256"]), None)


def recover_v021_case_reservation(
    *,
    authorization: VerifiedV021ExecutionAuthorization,
    case_id: str,
    request_sha256: str,
    call_id: str,
    durable_response_sha256: str | None,
) -> V021CaseReservation:
    auth = require_v021_execution_authorization(authorization)
    _require_case(auth, case_id)
    snapshot = verify_v021_spend_ledger(auth.ledger_path, authorization=auth)
    state = snapshot.case_states[case_id]
    request = _sha(request_sha256)
    call = _sha(call_id)
    if request != auth.request_sha256_by_case[case_id]:
        raise _reject("Recovery request differs from the authorization-bound request envelope.")
    if (
        state["request_sha256"] != request
        or state["call_id"] != call
        or state["state"] == "available"
    ):
        raise _reject("Recovery request does not match an irreversible reservation.")
    response = None if durable_response_sha256 is None else _sha(durable_response_sha256)
    recorded_response = cast(str | None, state["response_sha256"])
    if recorded_response is None and response is None:
        raise _reject(
            "unknown_spend_halt: reservation has no durable response; never retry provider."
        )
    if recorded_response is not None and response is not None and response != recorded_response:
        raise _reject("Durable response differs from the ledger-bound response.")
    return _reservation(
        auth,
        case_id,
        request,
        call,
        cast(str, state["reservation_event_sha256"]),
        recorded_response or response,
    )


def record_v021_provider_response(
    *,
    authorization: VerifiedV021ExecutionAuthorization,
    reservation: V021CaseReservation,
    response_sha256: str,
    actual_cost_usd: str,
    recorded_at: str,
) -> VerifiedV021SpendLedger:
    auth = require_v021_execution_authorization(authorization)
    _require_reservation(auth, reservation)
    response = _sha(response_sha256)
    cost = _cost(actual_cost_usd, PER_CASE_CAP_USD)
    with _locked(auth) as stream:
        snapshot = verify_v021_spend_ledger(auth.ledger_path, authorization=auth)
        _assert_stream_matches(stream, auth.ledger_path, snapshot.sha256)
        state = snapshot.case_states[reservation.case_id]
        _match_reservation(state, reservation)
        if state["response_sha256"] is not None:
            if state["response_sha256"] == response and state["actual_cost_usd"] == _money(cost):
                return snapshot
            raise _reject("A different response is already bound to this reservation.")
        if reservation.durable_response_sha256 not in {None, response}:
            raise _reject("Recovered durable response does not match the recorded response.")
        total = Decimal(snapshot.actual_cost_usd) + cost
        if total > Decimal(TOTAL_CAP_USD):
            raise _reject("Response cost exceeds the exact total cap; zero overage is allowed.")
        _append_locked(
            stream,
            auth,
            snapshot,
            "provider_response_durable",
            reservation.case_id,
            _timestamp(recorded_at),
            {
                "actual_cost_usd": _money(cost),
                "call_id": reservation.call_id,
                "request_sha256": reservation.request_sha256,
                "response_sha256": response,
                "reservation_event_sha256": reservation.reservation_event_sha256,
            },
        )
    return verify_v021_spend_ledger(auth.ledger_path, authorization=auth)


def record_v021_case_result(
    *,
    authorization: VerifiedV021ExecutionAuthorization,
    reservation: V021CaseReservation,
    response_sha256: str,
    result_sha256: str,
    recorded_at: str,
) -> VerifiedV021SpendLedger:
    auth = require_v021_execution_authorization(authorization)
    _require_reservation(auth, reservation)
    response, result = _sha(response_sha256), _sha(result_sha256)
    with _locked(auth) as stream:
        snapshot = verify_v021_spend_ledger(auth.ledger_path, authorization=auth)
        _assert_stream_matches(stream, auth.ledger_path, snapshot.sha256)
        state = snapshot.case_states[reservation.case_id]
        _match_reservation(state, reservation)
        if state["response_sha256"] != response:
            raise _reject("Result response does not match the case's durable response.")
        if state["result_sha256"] is not None:
            if state["result_sha256"] == result:
                return snapshot
            raise _reject("A different result is already bound to this case.")
        _append_locked(
            stream,
            auth,
            snapshot,
            "case_completed",
            reservation.case_id,
            _timestamp(recorded_at),
            {
                "call_id": reservation.call_id,
                "request_sha256": reservation.request_sha256,
                "response_sha256": response,
                "result_sha256": result,
                "reservation_event_sha256": reservation.reservation_event_sha256,
            },
        )
    return verify_v021_spend_ledger(auth.ledger_path, authorization=auth)


def _derive_states(
    events: list[dict[str, object]], auth: VerifiedV021ExecutionAuthorization
) -> tuple[dict[str, dict[str, object]], Decimal]:
    states: dict[str, dict[str, object]] = {
        case: {
            "state": "available",
            "request_sha256": None,
            "call_id": None,
            "reservation_event_sha256": None,
            "response_sha256": None,
            "actual_cost_usd": None,
            "result_sha256": None,
        }
        for case in auth.case_ids
    }
    total = Decimal("0")
    for event in events[1:]:
        event_type, case = event["event_type"], event["case_id"]
        if not isinstance(case, str) or case not in states:
            raise _reject("Ledger event uses a case outside the authorized cohort.")
        payload = cast(dict[str, object], event["payload"])
        state = states[case]
        if event_type == "case_reserved":
            if state["state"] != "available" or payload.get("maximum_cost_usd") != PER_CASE_CAP_USD:
                raise _reject("Duplicate or malformed reservation in ledger.")
            state.update(
                state="reserved_unknown_spend",
                request_sha256=_sha(payload.get("request_sha256")),
                call_id=_sha(payload.get("call_id")),
                reservation_event_sha256=event["event_sha256"],
            )
        elif event_type == "provider_response_durable":
            if state["state"] != "reserved_unknown_spend":
                raise _reject("Provider response does not follow exactly one reservation.")
            _match_payload(state, payload)
            cost = _cost(payload.get("actual_cost_usd"), PER_CASE_CAP_USD)
            total += cost
            if total > Decimal(TOTAL_CAP_USD):
                raise _reject("Ledger exceeds the exact total spend cap.")
            state.update(
                state="response_durable",
                response_sha256=_sha(payload.get("response_sha256")),
                actual_cost_usd=_money(cost),
            )
        elif event_type == "case_completed":
            if state["state"] != "response_durable":
                raise _reject("Case result does not follow a durable provider response.")
            _match_payload(state, payload)
            if payload.get("response_sha256") != state["response_sha256"]:
                raise _reject("Case result crosses provider response identities.")
            state.update(state="completed", result_sha256=_sha(payload.get("result_sha256")))
        else:
            raise _reject("Ledger event type is invalid.")
    return states, total


def _match_payload(state: Mapping[str, object], payload: Mapping[str, object]) -> None:
    if (
        payload.get("request_sha256") != state["request_sha256"]
        or payload.get("call_id") != state["call_id"]
        or payload.get("reservation_event_sha256") != state["reservation_event_sha256"]
    ):
        raise _reject("Ledger event crosses case reservation identities.")


def _match_reservation(state: Mapping[str, object], reservation: V021CaseReservation) -> None:
    if (
        state["request_sha256"] != reservation.request_sha256
        or state["call_id"] != reservation.call_id
        or state["reservation_event_sha256"] != reservation.reservation_event_sha256
    ):
        raise _reject("Reservation does not match the ledger case state.")


def _reservation(
    auth: VerifiedV021ExecutionAuthorization,
    case_id: str,
    request: str,
    call_id: str,
    event_sha: str,
    response: str | None,
) -> V021CaseReservation:
    value = object.__new__(V021CaseReservation)
    for name, item in {
        "authorization_sha256": auth.sha256,
        "ledger_identity_sha256": auth.ledger_identity_sha256,
        "case_id": case_id,
        "request_sha256": request,
        "call_id": call_id,
        "reservation_event_sha256": event_sha,
        "durable_response_sha256": response,
        "_issuer": _RESERVATION_ISSUER,
    }.items():
        object.__setattr__(value, name, item)
    return value


def _require_reservation(
    auth: VerifiedV021ExecutionAuthorization, value: object
) -> V021CaseReservation:
    if (
        type(value) is not V021CaseReservation
        or value._issuer is not _RESERVATION_ISSUER
        or value.authorization_sha256 != auth.sha256
        or value.ledger_identity_sha256 != auth.ledger_identity_sha256
    ):
        raise _reject("Ledger-issued reservation for this authorization is required.")
    return value


def _append_locked(
    stream: BinaryIO,
    auth: VerifiedV021ExecutionAuthorization,
    snapshot: VerifiedV021SpendLedger,
    event_type: str,
    case_id: str,
    recorded_at: str,
    payload: dict[str, object],
) -> dict[str, object]:
    _assert_locked_identity(stream, auth.ledger_path)
    event = _event(
        auth,
        sequence=len(snapshot.events) + 1,
        previous=snapshot.head_event_sha256,
        event_type=event_type,
        case_id=case_id,
        recorded_at=recorded_at,
        payload=payload,
    )
    stream.seek(0, os.SEEK_END)
    stream.write(_canonical(event) + b"\n")
    stream.flush()
    os.fsync(stream.fileno())
    _assert_locked_identity(stream, auth.ledger_path)
    return event


def _event(
    auth: VerifiedV021ExecutionAuthorization,
    *,
    sequence: int,
    previous: str | None,
    event_type: str,
    case_id: str | None,
    recorded_at: str,
    payload: dict[str, object],
) -> dict[str, object]:
    body = dict(payload)
    body["previous_event_sha256"] = previous
    event: dict[str, object] = {
        "algorithm": ALGORITHM,
        "authorization_sha256": auth.sha256,
        "benchmark_version": "0.2.1",
        "case_id": case_id,
        "event_type": event_type,
        "ledger_identity_sha256": auth.ledger_identity_sha256,
        "lineage_commitment_sha256": auth.lineage_commitment_sha256,
        "payload": body,
        "preregistration_sha256": auth.preregistration_sha256,
        "recorded_at": recorded_at,
        "request_set_sha256": auth.request_set_sha256,
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
    }
    event["event_sha256"] = _hash_without(event, "event_sha256")
    return event


class _locked:
    def __init__(self, authorization: VerifiedV021ExecutionAuthorization) -> None:
        self.authorization = authorization
        self.path = authorization.ledger_path
        self.stream: BinaryIO | None = None
        self.guard_descriptor: int | None = None

    def __enter__(self) -> BinaryIO:
        if self.path.is_symlink():
            raise _reject("Symlink ledger is forbidden.")
        guard_path = _ledger_guard_path(self.authorization)
        guard_flags = (
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            self.guard_descriptor = os.open(guard_path, guard_flags, 0o600)
            guard_stat = os.fstat(self.guard_descriptor)
            if not stat.S_ISREG(guard_stat.st_mode) or guard_stat.st_nlink != 1:
                raise _reject("Trusted ledger guard metadata is unsafe.")
            os.fchmod(self.guard_descriptor, 0o600)
            fcntl.flock(self.guard_descriptor, fcntl.LOCK_EX)
        except (OSError, PolicyRejection) as exc:
            if self.guard_descriptor is not None:
                os.close(self.guard_descriptor)
                self.guard_descriptor = None
            if isinstance(exc, PolicyRejection):
                raise
            raise _reject("Cannot acquire the trusted ledger guard.") from exc
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            self._release_guard()
            raise _reject("Ledger could not be opened without following links.") from exc
        self.stream = os.fdopen(descriptor, "r+b", buffering=0)
        fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX)
        try:
            _assert_locked_identity(self.stream, self.path)
        except BaseException:
            self.stream.close()
            self.stream = None
            self._release_guard()
            raise
        return self.stream

    def __exit__(self, *_args: object) -> None:
        if self.stream is not None:
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            self.stream.close()
        self._release_guard()

    def _release_guard(self) -> None:
        if self.guard_descriptor is not None:
            fcntl.flock(self.guard_descriptor, fcntl.LOCK_UN)
            os.close(self.guard_descriptor)
            self.guard_descriptor = None


def _ledger_guard_path(auth: VerifiedV021ExecutionAuthorization) -> Path:
    identity = hashlib.sha256(
        _canonical(
            {
                "preregistration_sha256": auth.preregistration_sha256,
                "request_set_sha256": auth.request_set_sha256,
            }
        )
    ).hexdigest()
    return _claim_state_root() / f"{identity}.ledger.lock"


def _assert_locked_identity(stream: BinaryIO, path: Path) -> None:
    descriptor_stat = os.fstat(stream.fileno())
    try:
        path_stat = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise _reject("Ledger path changed while its trusted guard was held.") from exc
    if (
        not stat.S_ISREG(descriptor_stat.st_mode)
        or descriptor_stat.st_nlink != 1
        or not stat.S_ISREG(path_stat.st_mode)
        or path_stat.st_nlink != 1
        or descriptor_stat.st_dev != path_stat.st_dev
        or descriptor_stat.st_ino != path_stat.st_ino
    ):
        raise _reject("Ledger inode changed while its trusted guard was held.")


def _assert_stream_matches(stream: BinaryIO, path: Path, expected_sha256: str) -> None:
    _assert_locked_identity(stream, path)
    stream.seek(0)
    raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise _reject("Verified ledger bytes differ from the locked ledger inode.")
    _assert_locked_identity(stream, path)


def _load_claim(path: Path, auth: VerifiedV021ExecutionAuthorization) -> dict[str, object]:
    record = _decode_object(_read(path, 64 * 1024, "ledger claim"), "ledger claim")
    if set(record) != {
        "algorithm",
        "authorization_sha256",
        "claim_sha256",
        "claimed_at",
        "ledger_absolute_path",
        "ledger_identity_sha256",
        "schema_version",
    }:
        raise _reject("Ledger claim fields are invalid.")
    if (
        record.get("algorithm") != CLAIM_ALGORITHM
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("authorization_sha256") != auth.sha256
        or record.get("ledger_absolute_path") != str(auth.ledger_path)
        or record.get("ledger_identity_sha256") != auth.ledger_identity_sha256
        or record.get("claim_sha256") != _hash_without(record, "claim_sha256")
    ):
        raise _reject("Ledger claim differs from its authorization.")
    _timestamp(record.get("claimed_at"))
    return record


def _decode_events(raw: bytes) -> list[dict[str, object]]:
    if not raw.endswith(b"\n") or b"\n\n" in raw:
        raise _reject("Ledger must be canonical newline-delimited JSON.")
    rows: list[dict[str, object]] = []
    for line in raw[:-1].split(b"\n"):
        try:
            value = json.loads(line, object_pairs_hook=_no_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise _reject("Ledger contains invalid JSON.") from exc
        if not isinstance(value, dict) or line != _canonical(value):
            raise _reject("Ledger event is not canonical JSON.")
        rows.append(cast(dict[str, object], value))
    return rows


def _decode_object(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject(f"{label.capitalize()} is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject(f"{label.capitalize()} is not canonical JSON.")
    return cast(dict[str, object], value)


def _read(path: Path, maximum: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            raw = stream.read(maximum + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label.capitalize()} could not be read safely.") from exc
    if not raw or len(raw) > maximum:
        raise _reject(f"{label.capitalize()} exceeds its byte bound.")
    return raw


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _claim_path(auth: VerifiedV021ExecutionAuthorization) -> Path:
    return _claim_state_root() / (
        f"{auth.sha256}.{auth.ledger_identity_sha256}.authorization-claim.json"
    )


def _claim_state_root() -> Path:
    """Return trusted user state outside caller-controlled campaign directories."""

    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    except (KeyError, OSError, RuntimeError) as exc:
        raise _reject("Cannot resolve the trusted authorization-claim state root.") from exc
    root = home / ".local" / "state" / "reproassert" / "v021-authorization-claims"
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
    except OSError as exc:
        raise _reject("Cannot prepare the trusted authorization-claim state root.") from exc
    require_private_directory(root)
    return root


def _require_case(auth: VerifiedV021ExecutionAuthorization, case_id: str) -> None:
    if case_id not in auth.case_ids:
        raise _reject("Case is outside the authorized cohort.")


def _sha(value: object) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise _reject("SHA-256 commitment is invalid.")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise _reject("Timestamp is invalid.")
    try:
        _time_value(value)
    except ValueError as exc:
        raise _reject("Timestamp is invalid.") from exc
    return value


def _time_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _cost(value: object, maximum: str) -> Decimal:
    if not isinstance(value, str):
        raise _reject("Cost must be an exact decimal string.")
    try:
        cost = Decimal(value)
    except InvalidOperation as exc:
        raise _reject("Cost is invalid.") from exc
    if not cost.is_finite() or cost < 0 or cost > Decimal(maximum) or value != _money(cost):
        raise _reject("Cost exceeds its cap or is not canonical USD.")
    return cost


def _money(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.000001')):.6f}"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _hash_without(record: Mapping[str, object], name: str) -> str:
    unsigned = dict(record)
    unsigned.pop(name, None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_ledger", message)
