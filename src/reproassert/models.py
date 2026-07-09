from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ClaimLevel(str, Enum):
    REJECTED = "rejected"
    COLLECTED = "collected"
    REPEATABLE_BASE_FAILURE = "repeatable_base_failure"
    DIFFERENTIAL_REPRODUCTION = "differential_reproduction"
    MAINTAINER_VALIDATED = "maintainer_validated"


@dataclass(frozen=True)
class IssueRef:
    url: str
    owner: str
    repo: str
    number: int
    title: str
    body_sha256: str


@dataclass(frozen=True)
class SourceSnapshot:
    repository_url: str
    requested_ref: str
    sha: str
    archive_sha256: str
    file_count: int
    unpacked_bytes: int


@dataclass(frozen=True)
class Candidate:
    relative_path: str
    test_function: str
    test_content_sha256: str
    expected_symptom: str
    rationale: str
    generator: str
    attempt: int


@dataclass(frozen=True)
class PhaseResult:
    phase: str
    status: str
    exit_code: int | None
    duration_seconds: float
    timed_out: bool = False
    oom_killed: bool = False
    output_truncated: bool = False
    output: str = ""
    rejection_code: str | None = None


@dataclass(frozen=True)
class VerificationRun:
    attempt: int
    exit_code: int | None
    status: str
    fingerprint: str | None
    duration_seconds: float
    output: str
    timed_out: bool = False
    oom_killed: bool = False
    output_truncated: bool = False


@dataclass
class ReproReport:
    schema_version: str
    report_id: str
    created_at: str
    tool_version: str
    claim_level: ClaimLevel
    outcome: str
    issue: IssueRef
    source: SourceSnapshot
    candidate: Candidate
    runner: dict[str, Any]
    policy: dict[str, Any]
    phases: list[PhaseResult] = field(default_factory=list)
    runs: list[VerificationRun] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    cleanup: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["claim_level"] = self.claim_level.value
        return result
