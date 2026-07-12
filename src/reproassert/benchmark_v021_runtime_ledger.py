"""Concrete v0.2.1 runtime port over the irreversible spend ledger."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from reproassert.benchmark_v021_authorization import VerifiedV021ExecutionAuthorization
from reproassert.benchmark_v021_ledger import (
    record_v021_case_result,
    record_v021_provider_response,
    recover_v021_case_reservation,
    reserve_v021_case,
    verify_v021_spend_ledger,
)
from reproassert.benchmark_v021_runtime import V021LedgerCaseState
from reproassert.errors import PolicyRejection


class V021SpendLedgerPort:
    """Adapt verifier-issued ledger operations to the generation runtime protocol."""

    def __init__(self, authorization: VerifiedV021ExecutionAuthorization) -> None:
        self.authorization = authorization
        verify_v021_spend_ledger(authorization.ledger_path, authorization=authorization)

    def state(self, case_id: str, request_sha256: str) -> V021LedgerCaseState:
        snapshot = verify_v021_spend_ledger(
            self.authorization.ledger_path, authorization=self.authorization
        )
        state = snapshot.case_states[case_id]
        if state["request_sha256"] not in {None, request_sha256}:
            raise _reject("Runtime request differs from the ledger-bound case request.")
        mapped = {
            "available": "unreserved",
            "reserved_unknown_spend": "reserved",
            "response_durable": "response_recorded",
            "completed": "result_recorded",
        }.get(str(state["state"]))
        if mapped is None:
            raise _reject("Ledger exposes an unsupported runtime state.")
        return V021LedgerCaseState(
            mapped,
            response_sha256=_optional_sha(state["response_sha256"]),
            result_sha256=_optional_sha(state["result_sha256"]),
        )

    def reserve(self, case_id: str, request_sha256: str, call_id: str) -> None:
        reserve_v021_case(
            authorization=self.authorization,
            case_id=case_id,
            request_sha256=request_sha256,
            call_id=call_id,
            reserved_at=_now(),
        )

    def record_response(
        self, case_id: str, request_sha256: str, response_sha256: str, cost_microusd: int
    ) -> None:
        call_id = _call_id(self.authorization.sha256, case_id, request_sha256)
        reservation = recover_v021_case_reservation(
            authorization=self.authorization,
            case_id=case_id,
            request_sha256=request_sha256,
            call_id=call_id,
            durable_response_sha256=response_sha256,
        )
        record_v021_provider_response(
            authorization=self.authorization,
            reservation=reservation,
            response_sha256=response_sha256,
            actual_cost_usd=f"{cost_microusd / 1_000_000:.6f}",
            recorded_at=_now(),
        )

    def record_result(
        self, case_id: str, request_sha256: str, response_sha256: str, result_sha256: str
    ) -> None:
        call_id = _call_id(self.authorization.sha256, case_id, request_sha256)
        reservation = recover_v021_case_reservation(
            authorization=self.authorization,
            case_id=case_id,
            request_sha256=request_sha256,
            call_id=call_id,
            durable_response_sha256=response_sha256,
        )
        record_v021_case_result(
            authorization=self.authorization,
            reservation=reservation,
            response_sha256=response_sha256,
            result_sha256=result_sha256,
            recorded_at=_now(),
        )

    def record_unknown_spend_halt(self, case_id: str, request_sha256: str, call_id: str) -> None:
        snapshot = verify_v021_spend_ledger(
            self.authorization.ledger_path, authorization=self.authorization
        )
        state = snapshot.case_states[case_id]
        if (
            state["state"] != "reserved_unknown_spend"
            or state["request_sha256"] != request_sha256
            or state["call_id"] != call_id
        ):
            raise _reject("Unknown-spend halt does not match the irreversible reservation.")


def _call_id(authorization_sha256: str, case_id: str, request_sha256: str) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "authorization_sha256": authorization_sha256,
                "case_id": case_id,
                "request_sha256": request_sha256,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def _optional_sha(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 64:
        raise _reject("Ledger digest is invalid.")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_runtime_ledger", message)
