from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from reproassert.benchmark_v02_execution_freeze import (
    MAX_CASE_MICROUSD,
    _preparation_requests,
    _required_reservation,
    exact_approval_statement,
)
from reproassert.benchmark_v02_runner import V02PricingSnapshot
from reproassert.errors import PolicyRejection


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    )


def _pricing() -> V02PricingSnapshot:
    return V02PricingSnapshot(
        provider="openai",
        requested_model="gpt-5.4-mini-2026-03-17",
        effective_at="2026-07-10T00:00:00Z",
        source="official pricing fixture",
        input_microusd_per_million_tokens=750_000,
        cached_input_microusd_per_million_tokens=75_000,
        output_microusd_per_million_tokens=4_500_000,
        sandbox_microusd_per_second=0,
        artifact_microusd_per_million_bytes=0,
        paid_storage_microusd=0,
        dependency_prep_microusd=0,
    )


def _request_preparation(
    root: Path, *, tool_git_sha: str, rendered_bytes: int
) -> dict[str, object]:
    packages: list[dict[str, object]] = []
    for position in range(1, 21):
        case_id = f"rk-v0.2-{position:03d}"
        request_path = Path("cases") / case_id / "request-envelope.json"
        package_path = Path("cases") / case_id / "package.json"
        (root / request_path).parent.mkdir(parents=True)
        rendered = "x" * rendered_bytes
        request = {
            "case_id": case_id,
            "provider_request": {"input": rendered},
            "rendered_input_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
            "tool_git_sha": tool_git_sha,
        }
        request_raw = _canonical(request)
        (root / request_path).write_bytes(request_raw)
        package = {
            "request_envelope": {
                "path": request_path.as_posix(),
                "sha256": hashlib.sha256(request_raw).hexdigest(),
            }
        }
        (root / package_path).write_bytes(_canonical(package))
        packages.append({"case_id": case_id, "path": package_path.as_posix()})
    return {"packages": packages}


def test_preparation_requests_bind_exact_rendered_bytes_and_controller_sha(tmp_path: Path) -> None:
    tool_sha = "9" * 40
    preparation = _request_preparation(tmp_path, tool_git_sha=tool_sha, rendered_bytes=100)
    case_ids = tuple(f"rk-v0.2-{position:03d}" for position in range(1, 21))

    rows = _preparation_requests(tmp_path, preparation, case_ids, controller_git_sha=tool_sha)

    assert len(rows) == 20
    assert all(rendered_bytes == 100 for _, _, rendered_bytes in rows)
    with pytest.raises(PolicyRejection, match="controller SHA"):
        _preparation_requests(tmp_path, preparation, case_ids, controller_git_sha="8" * 40)


def test_reservation_audit_rejects_known_oversize_requests() -> None:
    pricing = _pricing()

    assert _required_reservation(pricing, 374_714) == 299_468
    assert _required_reservation(pricing, 380_607) == 303_888
    assert _required_reservation(pricing, 300_000) <= MAX_CASE_MICROUSD
    assert _required_reservation(pricing, 374_714) > MAX_CASE_MICROUSD


def test_approval_statement_binds_final_freeze_hash_and_exact_caps() -> None:
    digest = "a" * 64
    statement = exact_approval_statement(digest)
    assert digest in statement
    assert "USD 5.00 total" in statement
    assert "USD 0.25 per-case" in statement
    assert "zero overage" in statement


def test_schema_is_bundled_strict_and_provider_code_reads_no_key() -> None:
    root = Path(__file__).parents[1]
    for filename in (
        "benchmark-v02-execution-freeze.schema.json",
        "benchmark-v02-exact-image-authorization.schema.json",
    ):
        public = root / "schemas" / filename
        bundled = root / "src/reproassert/schemas" / filename
        assert public.read_bytes() == bundled.read_bytes()
        jsonschema.Draft202012Validator.check_schema(json.loads(public.read_text()))
    source = (root / "src/reproassert/benchmark_v02_execution_freeze.py").read_text()
    assert "OPENAI_API_KEY" not in source
    assert "os.environ" not in source
    assert "exact_approval_statement" in source
