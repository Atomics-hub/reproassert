"""Uniform all-20 controller for the v0.2.1 runtime kernel."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from reproassert.benchmark_v021_runtime import (
    ExecutionAuthorization,
    ProviderAdapter,
    V021GenerationResult,
    V021LedgerPort,
    VerifiedV021RuntimePlan,
    execute_v021_case,
    require_v021_runtime_plan,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import require_private_directory, write_bytes_exclusive

BARRIER_ALGORITHM = "reproassert-v021-generation-barrier-v1"
PROGRESS_ALGORITHM = "reproassert-v021-campaign-progress-v1"
_BARRIER_ISSUER = object()


@dataclass(frozen=True, init=False)
class VerifiedV021GenerationBarrier:
    sha256: str
    authorization_sha256: str
    request_set_sha256: str
    result_sha256_by_case: dict[str, str] = field(repr=False)
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV021GenerationBarrier is controller-issued only")


@dataclass(frozen=True)
class V021CampaignRun:
    status: str
    results: tuple[V021GenerationResult, ...]
    barrier: VerifiedV021GenerationBarrier | None


def require_v021_generation_barrier(value: object) -> VerifiedV021GenerationBarrier:
    """Require the controller-issued all-20 terminal generation barrier."""

    if type(value) is not VerifiedV021GenerationBarrier or value._issuer is not _BARRIER_ISSUER:
        raise _reject("Controller-issued v0.2.1 generation barrier is required.")
    expected = tuple(f"rk-v0.2-{index:03d}" for index in range(1, 21))
    if tuple(value.result_sha256_by_case) != expected:
        raise _reject("Generation barrier does not preserve the exact 20-case denominator.")
    for digest in (
        value.sha256,
        value.authorization_sha256,
        value.request_set_sha256,
        *value.result_sha256_by_case.values(),
    ):
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise _reject("Generation barrier contains an invalid digest.")
    record = {
        "algorithm": BARRIER_ALGORITHM,
        "authorization_sha256": value.authorization_sha256,
        "request_set_sha256": value.request_set_sha256,
        "results": value.result_sha256_by_case,
    }
    if hashlib.sha256(_canonical(record)).hexdigest() != value.sha256:
        raise _reject("Generation barrier identity is invalid.")
    return value


def run_v021_generation_campaign(
    *,
    plan: VerifiedV021RuntimePlan,
    authorization: ExecutionAuthorization,
    ledger: V021LedgerPort,
    provider: ProviderAdapter,
    response_directory: Path,
    result_directory: Path,
    progress_path: Path,
) -> V021CampaignRun:
    """Run the exact 20-case generation phase under a single campaign lock."""

    verified = require_v021_runtime_plan(plan)
    if authorization.sha256 != verified.authorization_sha256:
        raise _reject("Campaign authorization differs from the verified runtime plan.")
    response_root, result_root, progress = (
        Path(response_directory),
        Path(result_directory),
        Path(progress_path),
    )
    require_private_directory(response_root)
    require_private_directory(result_root)
    require_private_directory(progress.parent)
    descriptor = _acquire_lock(progress.parent, verified)
    try:
        results: list[V021GenerationResult] = []
        for row in verified.cases:
            result = execute_v021_case(
                plan=verified,
                authorization=authorization,
                ledger=ledger,
                case_id=str(row["case_id"]),
                provider=provider,
                response_directory=response_root,
                result_directory=result_root,
            )
            results.append(result)
            _write_progress(progress, verified, results, "generation")
            if result.outcome == "unknown_spend_halt":
                _write_progress(progress, verified, results, "unknown_spend_halt")
                return V021CampaignRun(
                    status="unknown_spend_halt", results=tuple(results), barrier=None
                )
        barrier = _issue_barrier(verified, results)
        _write_progress(progress, verified, results, "generation_complete", barrier.sha256)
        return V021CampaignRun(
            status="generation_complete", results=tuple(results), barrier=barrier
        )
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _issue_barrier(
    plan: VerifiedV021RuntimePlan, results: list[V021GenerationResult]
) -> VerifiedV021GenerationBarrier:
    expected = tuple(f"rk-v0.2-{index:03d}" for index in range(1, 21))
    if tuple(result.case_id for result in results) != expected:
        raise _reject("Generation barrier requires all 20 canonical terminal dispositions.")
    if any(result.outcome != "provider_response_durable_unparsed" for result in results):
        raise _reject("Generation barrier cannot include unknown-spend or nonterminal cases.")
    bindings = {result.case_id: result.sha256 for result in results}
    record = {
        "algorithm": BARRIER_ALGORITHM,
        "authorization_sha256": plan.authorization_sha256,
        "request_set_sha256": plan.request_set_sha256,
        "results": bindings,
    }
    authority = object.__new__(VerifiedV021GenerationBarrier)
    for name, value in {
        "sha256": hashlib.sha256(_canonical(record)).hexdigest(),
        "authorization_sha256": plan.authorization_sha256,
        "request_set_sha256": plan.request_set_sha256,
        "result_sha256_by_case": bindings,
        "_issuer": _BARRIER_ISSUER,
    }.items():
        object.__setattr__(authority, name, value)
    return authority


def _acquire_lock(directory: Path, plan: VerifiedV021RuntimePlan) -> int:
    path = directory / ".reproassert-v021-controller.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise _reject("Cannot safely open the v0.2.1 controller lock.") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise _reject("v0.2.1 controller lock metadata is unsafe.")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise _reject("Another v0.2.1 campaign controller owns the lock.") from exc
            raise
        identity = (
            _canonical(
                {
                    "algorithm": "reproassert-v021-controller-lock-v1",
                    "authorization_sha256": plan.authorization_sha256,
                    "plan_sha256": plan.sha256,
                }
            )
            + b"\n"
        )
        existing = os.read(descriptor, 4097)
        if existing and existing != identity:
            raise _reject("Controller lock belongs to a different campaign.")
        if not existing:
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.write(descriptor, identity)
            os.fsync(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_progress(
    path: Path,
    plan: VerifiedV021RuntimePlan,
    results: list[V021GenerationResult],
    status: str,
    barrier_sha256: str | None = None,
) -> None:
    record = {
        "algorithm": PROGRESS_ALGORITHM,
        "authorization_sha256": plan.authorization_sha256,
        "barrier_sha256": barrier_sha256,
        "case_count": len(results),
        "results": {result.case_id: result.sha256 for result in results},
        "status": status,
    }
    raw = _canonical(record) + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    write_bytes_exclusive(temporary, raw)
    os.replace(temporary, path)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_campaign_controller", message)
