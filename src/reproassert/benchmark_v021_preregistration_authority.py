"""Nominal authority bridge for the two honest v0.2.1 preregistration modes."""

from __future__ import annotations

from typing import TypeAlias

from reproassert.benchmark_v021_automated_preregistration import (
    VerifiedV021AutomatedPreregistration,
    require_v021_automated_preregistration,
)
from reproassert.benchmark_v021_preregistration import (
    VerifiedV021Preregistration,
    require_v021_preregistration,
)
from reproassert.errors import PolicyRejection

V021ExecutionPreregistration: TypeAlias = (
    VerifiedV021Preregistration | VerifiedV021AutomatedPreregistration
)


def require_v021_execution_preregistration(
    value: object,
) -> V021ExecutionPreregistration:
    """Accept only one of the two verifier-issued nominal authorities."""

    if type(value) is VerifiedV021Preregistration:
        return require_v021_preregistration(value)
    if type(value) is VerifiedV021AutomatedPreregistration:
        return require_v021_automated_preregistration(value)
    raise PolicyRejection(
        "benchmark_v021_preregistration_authority",
        "Fresh verifier-issued v0.2.1 preregistration authority is required.",
    )


def v021_preregistration_mode(value: object) -> str:
    authority = require_v021_execution_preregistration(value)
    if type(authority) is VerifiedV021AutomatedPreregistration:
        return "automated_oracle"
    return "human_consensus"
