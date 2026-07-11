"""Provider-free preparation and consensus sealing for v0.2 fix-hunk mappings."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import cast

from reproassert.benchmark_v02_hidden import (
    VerifiedV02HiddenExtraction,
    hidden_case_artifacts,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import require_private_directory, write_bytes_exclusive

PREPARATION_ALGORITHM = "reproassert-v02-hunk-mapping-packets-v1"
CONSENSUS_ALGORITHM = "reproassert-v02-hunk-mapping-consensus-v1"
SCHEMA_VERSION = "1.0.0"
PREPARATION_FILENAME = "benchmark-v02-mapping-packet-set.json"
SEALED_FILENAME = "benchmark-v02-mapping-consensus-set.json"
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}\Z")
_HUNK = re.compile(rb"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: [^\r\n]*)?\r?\n\Z")
_MAX_PATCH_BYTES = 1024 * 1024
_MAX_JSON_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class MappingPacketPreparation:
    root: Path
    receipt_path: Path
    receipt_sha256: str
    case_count: int


@dataclass(frozen=True)
class MappingConsensusSet:
    path: Path
    sha256: str
    case_count: int


def inventory_unified_diff(patch: bytes, *, case_id: str) -> list[dict[str, object]]:
    """Parse a bounded text diff into stable, ordered atomic hunk commitments."""

    _case_id(case_id)
    if not patch or len(patch) > _MAX_PATCH_BYTES or b"\x00" in patch:
        raise _reject("Production patch must be non-empty bounded UTF-8 text.")
    try:
        patch.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _reject("Binary or non-UTF-8 production patches are forbidden.") from exc
    forbidden = (
        b"GIT binary patch",
        b"Binary files ",
        b"rename from ",
        b"rename to ",
        b"similarity index ",
        b"old mode ",
        b"new mode ",
        b"new file mode ",
        b"deleted file mode ",
    )
    lines = patch.splitlines(keepends=True)
    if any(line.startswith(forbidden) for line in lines):
        raise _reject("Binary, rename, create/delete, and mode-only diffs are forbidden.")

    result: list[dict[str, object]] = []
    file_path: str | None = None
    seen_paths: set[str] = set()
    previous_ranges: dict[str, tuple[int, int, int, int]] = {}
    index = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(b"diff --git "):
            parts = line.rstrip(b"\r\n").split(b" ")
            if len(parts) != 4 or not parts[2].startswith(b"a/") or not parts[3].startswith(b"b/"):
                raise _reject("Malformed diff --git header.")
            left = _safe_patch_path(parts[2][2:])
            right = _safe_patch_path(parts[3][2:])
            if left != right:
                raise _reject("Renames and path changes are forbidden.")
            file_path = left
            seen_paths.add(left)
            i += 1
            continue
        if line.startswith(b"--- "):
            if file_path is None or line.rstrip(b"\r\n") != f"--- a/{file_path}".encode():
                raise _reject("Old-file header does not match diff path.")
            if i + 1 >= len(lines) or lines[i + 1].rstrip(b"\r\n") != f"+++ b/{file_path}".encode():
                raise _reject("New-file header does not match diff path.")
            i += 2
            continue
        if line.startswith(b"@@ "):
            if file_path is None:
                raise _reject("Hunk appears before a file header.")
            match = _HUNK.fullmatch(line)
            if match is None:
                raise _reject("Malformed unified-diff hunk header.")
            old_start = int(match.group(1))
            old_count = int(match.group(2) or b"1")
            new_start = int(match.group(3))
            new_count = int(match.group(4) or b"1")
            if old_count < 0 or new_count < 0 or (old_count == 0 and new_count == 0):
                raise _reject("Degenerate hunk range is forbidden.")
            body: list[bytes] = []
            old_seen = new_seen = changed = 0
            i += 1
            while i < len(lines) and not lines[i].startswith((b"@@ ", b"diff --git ")):
                body_line = lines[i]
                if body_line.startswith(b"\\ No newline at end of file"):
                    body.append(body_line)
                    i += 1
                    continue
                if not body_line.startswith((b" ", b"+", b"-")):
                    raise _reject("Unexpected line inside unified-diff hunk.")
                marker = body_line[:1]
                old_seen += marker in (b" ", b"-")
                new_seen += marker in (b" ", b"+")
                changed += marker in (b"+", b"-")
                body.append(body_line)
                i += 1
            if old_seen != old_count or new_seen != new_count or changed == 0:
                raise _reject("Hunk counts are inconsistent or contain no semantic change.")
            old_end = old_start + old_count
            new_end = new_start + new_count
            previous = previous_ranges.get(file_path)
            if previous is not None:
                prev_old_start, prev_old_end, prev_new_start, prev_new_end = previous
                if old_start <= prev_old_end or new_start <= prev_new_end:
                    raise _reject(
                        "Overlapping, reordered, or degenerately split hunks are forbidden."
                    )
                del prev_old_start, prev_new_start
            previous_ranges[file_path] = (old_start, old_end, new_start, new_end)
            index += 1
            hunk_bytes = line + b"".join(body)
            hunk_sha = hashlib.sha256(hunk_bytes).hexdigest()
            atom_material = _canonical(
                {
                    "case_id": case_id,
                    "hunk_sha256": hunk_sha,
                    "new_count": new_count,
                    "new_start": new_start,
                    "old_count": old_count,
                    "old_start": old_start,
                    "ordinal": index,
                    "path": file_path,
                }
            )
            atom_digest = hashlib.sha256(atom_material).hexdigest()[:16]
            result.append(
                {
                    "atomic_id": f"{case_id}:h{index:03d}:{atom_digest}",
                    "hunk_sha256": hunk_sha,
                    "new_count": new_count,
                    "new_start": new_start,
                    "old_count": old_count,
                    "old_start": old_start,
                    "ordinal": index,
                    "path": file_path,
                }
            )
            continue
        if line.startswith((b"index ", b"--- ", b"+++ ")) or not line.strip():
            i += 1
            continue
        raise _reject("Unexpected metadata outside a unified-diff hunk.")
    if not result or not seen_paths:
        raise _reject("Production patch contains no reviewable hunks.")
    return result


def prepare_v02_mapping_packets(
    *,
    verified_hidden: VerifiedV02HiddenExtraction,
    output_root: Path,
    prepared_at: str,
    tool_git_sha: str,
) -> MappingPacketPreparation:
    """Prepare 20 blank private review packets from freshly verified hidden gold."""

    _timestamp(prepared_at)
    _git_sha(tool_git_sha)
    root = Path(output_root)
    require_private_directory(root)
    destination = root / "v02-mapping-packets"
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite mapping packet preparation.")
    destination.mkdir(mode=0o700)
    try:
        cases: list[dict[str, object]] = []
        hidden_receipt_sha = verified_hidden.prepared.receipt_sha256
        for number in range(1, 21):
            case_id = f"rk-v0.2-{number:03d}"
            artifacts = hidden_case_artifacts(verified_hidden, case_id)
            source = cast(Path, artifacts["production_patch"]["path"])
            patch = _read_regular(source, _MAX_PATCH_BYTES)
            patch_sha = hashlib.sha256(patch).hexdigest()
            if patch_sha != artifacts["production_patch"]["sha256"]:
                raise _reject(f"{case_id} production patch changed after hidden verification.")
            hunks = inventory_unified_diff(patch, case_id=case_id)
            case_root = destination / "packets" / case_id
            case_root.mkdir(parents=True, mode=0o700)
            patch_path = case_root / "production.patch"
            write_bytes_exclusive(patch_path, patch)
            algebra = {
                "algorithm": "ordered-hunk-commitment-v1",
                "ordered_atomic_ids": [row["atomic_id"] for row in hunks],
                "ordered_hunk_sha256": [row["hunk_sha256"] for row in hunks],
                "production_patch_sha256": patch_sha,
            }
            algebra["commitment_sha256"] = hashlib.sha256(_canonical(algebra)).hexdigest()
            packet: dict[str, object] = {
                "case_id": case_id,
                "hidden_extraction_receipt_sha256": hidden_receipt_sha,
                "hunk_inventory": hunks,
                "patch_algebra": algebra,
                "prepared_at": prepared_at,
                "production_patch": {
                    "bytes": len(patch),
                    "path": "production.patch",
                    "sha256": patch_sha,
                },
                "provider_calls": 0,
                "reviews": [],
                "schema_version": SCHEMA_VERSION,
                "status": "awaiting_two_independent_mapping_reviews",
            }
            packet["packet_sha256"] = _self_hash(packet)
            packet_bytes = _canonical(packet) + b"\n"
            write_bytes_exclusive(case_root / "packet.json", packet_bytes)
            cases.append(
                {
                    "case_id": case_id,
                    "hunk_count": len(hunks),
                    "packet": _reference(destination, case_root / "packet.json"),
                    "patch_algebra_commitment_sha256": algebra["commitment_sha256"],
                    "production_patch_sha256": patch_sha,
                    "status": "review_required",
                }
            )
        receipt: dict[str, object] = {
            "algorithm": PREPARATION_ALGORITHM,
            "benchmark_version": "0.2",
            "case_count": 20,
            "cases": cases,
            "claims": {
                "model_or_provider_invoked": False,
                "provider_calls": 0,
                "reviewer_identity_or_verdict_generated": False,
            },
            "hidden_extraction_receipt_sha256": hidden_receipt_sha,
            "prepared_at": prepared_at,
            "schema_version": SCHEMA_VERSION,
            "status": "prepared_review_required_provider_disabled",
            "tool": {"git_sha": tool_git_sha, "name": "reproassert"},
        }
        receipt["receipt_sha256"] = _self_hash(receipt)
        path = destination / PREPARATION_FILENAME
        write_bytes_exclusive(path, _canonical(receipt) + b"\n")
        return verify_v02_mapping_packets(path)
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def verify_v02_mapping_packets(path: Path) -> MappingPacketPreparation:
    """Verify every packet, patch commitment, blank-review state, and self hash."""

    receipt_path = Path(path)
    root = receipt_path.parent
    require_private_directory(root)
    record = _load_json(receipt_path, _MAX_JSON_BYTES)
    _exact_keys(
        record,
        {
            "algorithm",
            "benchmark_version",
            "case_count",
            "cases",
            "claims",
            "hidden_extraction_receipt_sha256",
            "prepared_at",
            "receipt_sha256",
            "schema_version",
            "status",
            "tool",
        },
        "mapping preparation",
    )
    if record.get("algorithm") != PREPARATION_ALGORITHM or record.get("case_count") != 20:
        raise _reject("Mapping preparation identity or denominator is invalid.")
    if (
        record.get("benchmark_version") != "0.2"
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("status") != "prepared_review_required_provider_disabled"
        or record.get("claims")
        != {
            "model_or_provider_invoked": False,
            "provider_calls": 0,
            "reviewer_identity_or_verdict_generated": False,
        }
    ):
        raise _reject("Mapping preparation provider-free claims are invalid.")
    _timestamp(cast(str, record.get("prepared_at")))
    hidden_sha = record.get("hidden_extraction_receipt_sha256")
    if not isinstance(hidden_sha, str) or _SHA256.fullmatch(hidden_sha) is None:
        raise _reject("Mapping preparation hidden extraction commitment is invalid.")
    tool = _dict(record.get("tool"), "mapping preparation tool")
    _exact_keys(tool, {"git_sha", "name"}, "mapping preparation tool")
    if tool.get("name") != "reproassert":
        raise _reject("Mapping preparation tool identity is invalid.")
    _git_sha(cast(str, tool.get("git_sha")))
    if record.get("receipt_sha256") != _self_hash(record):
        raise _reject("Mapping preparation self hash is invalid.")
    cases = record.get("cases")
    if not isinstance(cases, list) or len(cases) != 20:
        raise _reject("Mapping preparation must contain exactly 20 cases.")
    expected = [f"rk-v0.2-{number:03d}" for number in range(1, 21)]
    if [row.get("case_id") for row in cases if isinstance(row, dict)] != expected:
        raise _reject("Mapping preparation cases are incomplete or out of order.")
    for raw in cases:
        row = _dict(raw, "mapping preparation case")
        _exact_keys(
            row,
            {
                "case_id",
                "hunk_count",
                "packet",
                "patch_algebra_commitment_sha256",
                "production_patch_sha256",
                "status",
            },
            "mapping preparation case",
        )
        if row.get("status") != "review_required":
            raise _reject("Mapping preparation case review status is invalid.")
        ref = _dict(row.get("packet"), "packet reference")
        packet_path = _resolve_ref(root, ref)
        packet = _load_json(packet_path, _MAX_JSON_BYTES)
        _exact_keys(
            packet,
            {
                "case_id",
                "hidden_extraction_receipt_sha256",
                "hunk_inventory",
                "packet_sha256",
                "patch_algebra",
                "prepared_at",
                "production_patch",
                "provider_calls",
                "reviews",
                "schema_version",
                "status",
            },
            "mapping packet",
        )
        if (
            packet.get("case_id") != row["case_id"]
            or packet.get("reviews") != []
            or packet.get("provider_calls") != 0
            or packet.get("schema_version") != SCHEMA_VERSION
            or packet.get("status") != "awaiting_two_independent_mapping_reviews"
            or packet.get("prepared_at") != record.get("prepared_at")
            or packet.get("hidden_extraction_receipt_sha256") != hidden_sha
        ):
            raise _reject("Prepared mapping packet is not blank or has the wrong case identity.")
        if packet.get("packet_sha256") != _self_hash(packet):
            raise _reject("Mapping packet self hash is invalid.")
        _verify_ref(root, ref)
        patch_ref = _dict(packet.get("production_patch"), "production patch reference")
        patch_path = _resolve_ref(packet_path.parent, patch_ref)
        _verify_ref(packet_path.parent, patch_ref)
        patch = _read_regular(patch_path, _MAX_PATCH_BYTES)
        hunks = inventory_unified_diff(patch, case_id=cast(str, row["case_id"]))
        if hunks != packet.get("hunk_inventory"):
            raise _reject("Stored hunk inventory differs from the production patch.")
        algebra = _dict(packet.get("patch_algebra"), "patch algebra")
        _exact_keys(
            algebra,
            {
                "algorithm",
                "commitment_sha256",
                "ordered_atomic_ids",
                "ordered_hunk_sha256",
                "production_patch_sha256",
            },
            "patch algebra",
        )
        commitment = algebra.get("commitment_sha256")
        if (
            commitment
            != hashlib.sha256(_canonical_without(algebra, "commitment_sha256")).hexdigest()
        ):
            raise _reject("Patch algebra commitment is invalid.")
        if commitment != row.get("patch_algebra_commitment_sha256"):
            raise _reject("Packet and preparation patch commitments differ.")
        if (
            algebra.get("algorithm") != "ordered-hunk-commitment-v1"
            or algebra.get("ordered_atomic_ids") != [item["atomic_id"] for item in hunks]
            or algebra.get("ordered_hunk_sha256") != [item["hunk_sha256"] for item in hunks]
            or algebra.get("production_patch_sha256") != hashlib.sha256(patch).hexdigest()
            or row.get("production_patch_sha256") != hashlib.sha256(patch).hexdigest()
            or row.get("hunk_count") != len(hunks)
        ):
            raise _reject("Patch algebra does not reconstruct the exact ordered hunk set.")
    raw = _read_regular(receipt_path, _MAX_JSON_BYTES)
    return MappingPacketPreparation(root, receipt_path, hashlib.sha256(raw).hexdigest(), 20)


def seal_v02_mapping_consensus(
    *, preparation_path: Path, submissions_root: Path, output_path: Path, sealed_at: str
) -> MappingConsensusSet:
    """Seal only authentic two-reviewer agreement, with a third reviewer only for a tie break."""

    prepared = verify_v02_mapping_packets(preparation_path)
    sealed_time = _timestamp(sealed_at)
    preparation = _load_json(prepared.receipt_path, _MAX_JSON_BYTES)
    prepared_time = _timestamp(cast(str, preparation["prepared_at"]))
    root = Path(submissions_root)
    require_private_directory(root)
    cases: list[dict[str, object]] = []
    for case_row_raw in cast(list[object], preparation["cases"]):
        case_row = _dict(case_row_raw, "mapping preparation case")
        case_id = cast(str, case_row["case_id"])
        packet_ref = _dict(case_row["packet"], "packet reference")
        packet = _load_json(_resolve_ref(prepared.root, packet_ref), _MAX_JSON_BYTES)
        packet_sha = cast(str, packet["packet_sha256"])
        allowed_ids = {
            cast(str, row["atomic_id"])
            for row in cast(list[dict[str, object]], packet["hunk_inventory"])
        }
        files = sorted((root / case_id).glob("*.json")) if (root / case_id).is_dir() else []
        if len(files) not in (2, 3):
            raise _reject(
                f"{case_id} requires exactly two submissions, or three after disagreement."
            )
        submissions = [
            _validate_submission(file, case_id, packet_sha, allowed_ids, prepared_time, sealed_time)
            for file in files
        ]
        reviewer_ids = [cast(str, value["reviewer_id"]) for value in submissions]
        if len(set(reviewer_ids)) != len(reviewer_ids):
            raise _reject(f"{case_id} reviewer identities must be independent and distinct.")
        signatures = [_decision_signature(value) for value in submissions]
        if signatures[0] == signatures[1]:
            if len(submissions) != 2:
                raise _reject(f"{case_id} forbids a tie-break reviewer when the first two agree.")
            chosen = submissions[0]
            mode = "two_reviewer_agreement"
        else:
            if len(submissions) != 3 or signatures[2] not in signatures[:2]:
                raise _reject(
                    f"{case_id} disagreement requires one genuine third tie-break decision."
                )
            chosen = submissions[2]
            mode = "third_reviewer_tiebreak"
        cases.append(
            {
                "case_id": case_id,
                "consensus": {
                    "mode": mode,
                    "selected_hunk_ids": chosen["selected_hunk_ids"],
                    "verdict": chosen["verdict"],
                },
                "packet_sha256": packet_sha,
                "reviewer_ids": reviewer_ids,
                "submissions": submissions,
            }
        )
    record: dict[str, object] = {
        "algorithm": CONSENSUS_ALGORITHM,
        "benchmark_version": "0.2",
        "case_count": 20,
        "cases": cases,
        "mapping_preparation_receipt_sha256": cast(str, preparation["receipt_sha256"]),
        "provider_calls": 0,
        "schema_version": SCHEMA_VERSION,
        "sealed_at": sealed_at,
        "status": "sealed_complete",
    }
    record["seal_sha256"] = _self_hash(record)
    if output_path.exists() or output_path.is_symlink():
        raise _reject("Refusing to overwrite an existing mapping consensus seal.")
    require_private_directory(output_path.parent)
    write_bytes_exclusive(output_path, _canonical(record) + b"\n")
    return verify_v02_mapping_consensus(output_path, preparation_path=preparation_path)


def verify_v02_mapping_consensus(path: Path, *, preparation_path: Path) -> MappingConsensusSet:
    preparation = verify_v02_mapping_packets(preparation_path)
    record = _load_json(path, _MAX_JSON_BYTES)
    _exact_keys(
        record,
        {
            "algorithm",
            "benchmark_version",
            "case_count",
            "cases",
            "mapping_preparation_receipt_sha256",
            "provider_calls",
            "schema_version",
            "seal_sha256",
            "sealed_at",
            "status",
        },
        "mapping consensus set",
    )
    if record.get("algorithm") != CONSENSUS_ALGORITHM or record.get("case_count") != 20:
        raise _reject("Mapping consensus identity or denominator is invalid.")
    if (
        record.get("benchmark_version") != "0.2"
        or record.get("provider_calls") != 0
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("status") != "sealed_complete"
    ):
        raise _reject("Mapping consensus sealed state is invalid.")
    if record.get("seal_sha256") != _self_hash(record):
        raise _reject("Mapping consensus self hash is invalid.")
    prep_record = _load_json(preparation.receipt_path, _MAX_JSON_BYTES)
    if record.get("mapping_preparation_receipt_sha256") != prep_record.get("receipt_sha256"):
        raise _reject("Mapping consensus does not bind the exact preparation.")
    cases = record.get("cases")
    if not isinstance(cases, list) or len(cases) != 20:
        raise _reject("Mapping consensus must preserve the full denominator.")
    prepared_at = _timestamp(cast(str, prep_record["prepared_at"]))
    sealed_at = _timestamp(cast(str, record.get("sealed_at")))
    prep_cases = cast(list[dict[str, object]], prep_record["cases"])
    expected_ids = [f"rk-v0.2-{number:03d}" for number in range(1, 21)]
    if [row.get("case_id") for row in cases if isinstance(row, dict)] != expected_ids:
        raise _reject("Mapping consensus cases are incomplete or out of order.")
    for raw_case, prep_case in zip(cases, prep_cases, strict=True):
        case = _dict(raw_case, "mapping consensus case")
        _exact_keys(
            case,
            {"case_id", "consensus", "packet_sha256", "reviewer_ids", "submissions"},
            "mapping consensus case",
        )
        case_id = cast(str, case["case_id"])
        packet = _load_json(
            _resolve_ref(preparation.root, _dict(prep_case["packet"], "packet reference")),
            _MAX_JSON_BYTES,
        )
        packet_sha = cast(str, packet["packet_sha256"])
        if case.get("packet_sha256") != packet_sha:
            raise _reject(f"{case_id} consensus binds the wrong packet.")
        allowed_ids = {
            cast(str, row["atomic_id"])
            for row in cast(list[dict[str, object]], packet["hunk_inventory"])
        }
        raw_submissions = case.get("submissions")
        if not isinstance(raw_submissions, list) or len(raw_submissions) not in (2, 3):
            raise _reject(f"{case_id} sealed reviewer submission count is invalid.")
        submissions = [
            _validate_submission_value(
                _dict(value, "sealed mapping review"),
                case_id,
                packet_sha,
                allowed_ids,
                prepared_at,
                sealed_at,
            )
            for value in raw_submissions
        ]
        reviewer_ids = [cast(str, value["reviewer_id"]) for value in submissions]
        if case.get("reviewer_ids") != reviewer_ids or len(set(reviewer_ids)) != len(reviewer_ids):
            raise _reject(f"{case_id} sealed reviewer identities are invalid.")
        signatures = [_decision_signature(value) for value in submissions]
        consensus = _dict(case.get("consensus"), "mapping consensus decision")
        if signatures[0] == signatures[1]:
            if len(submissions) != 2:
                raise _reject(f"{case_id} has an unnecessary tie-break submission.")
            chosen = submissions[0]
            expected_mode = "two_reviewer_agreement"
        else:
            if len(submissions) != 3 or signatures[2] not in signatures[:2]:
                raise _reject(f"{case_id} has no valid third-reviewer tie break.")
            chosen = submissions[2]
            expected_mode = "third_reviewer_tiebreak"
        if consensus != {
            "mode": expected_mode,
            "selected_hunk_ids": chosen["selected_hunk_ids"],
            "verdict": chosen["verdict"],
        }:
            raise _reject(f"{case_id} sealed consensus does not match its reviews.")
    raw = _read_regular(path, _MAX_JSON_BYTES)
    return MappingConsensusSet(Path(path), hashlib.sha256(raw).hexdigest(), 20)


def _validate_submission(
    path: Path,
    case_id: str,
    packet_sha: str,
    allowed_ids: set[str],
    prepared_at: datetime,
    sealed_at: datetime,
) -> dict[str, object]:
    return _validate_submission_value(
        _load_json(path, 64 * 1024),
        case_id,
        packet_sha,
        allowed_ids,
        prepared_at,
        sealed_at,
    )


def _validate_submission_value(
    value: dict[str, object],
    case_id: str,
    packet_sha: str,
    allowed_ids: set[str],
    prepared_at: datetime,
    sealed_at: datetime,
) -> dict[str, object]:
    required = {
        "case_id",
        "declarations",
        "packet_sha256",
        "reviewer_id",
        "schema_version",
        "selected_hunk_ids",
        "submitted_at",
        "verdict",
    }
    if set(value) != required or value["schema_version"] != SCHEMA_VERSION:
        raise _reject(f"{case_id} reviewer submission shape is invalid.")
    if value["case_id"] != case_id or value["packet_sha256"] != packet_sha:
        raise _reject(f"{case_id} reviewer submission binds the wrong packet.")
    reviewer = value["reviewer_id"]
    if not isinstance(reviewer, str) or _IDENTIFIER.fullmatch(reviewer) is None:
        raise _reject(f"{case_id} reviewer identity is invalid.")
    if any(
        token in reviewer.lower()
        for token in ("placeholder", "example", "reviewer-1", "reviewer-2", "tbd")
    ):
        raise _reject(f"{case_id} placeholder reviewer identities are forbidden.")
    declarations = value["declarations"]
    if declarations != {
        "generator_access": "forbidden",
        "independent_judgment": True,
        "role": "mapping_reviewer",
        "semantic_review_role": "forbidden",
    }:
        raise _reject(f"{case_id} role and conflict declarations are incomplete.")
    submitted = _timestamp(cast(str, value["submitted_at"]))
    if submitted <= prepared_at or submitted > sealed_at:
        raise _reject(f"{case_id} review chronology is invalid.")
    verdict = value["verdict"]
    ids = value["selected_hunk_ids"]
    if verdict not in ("approved", "rejected") or not isinstance(ids, list):
        raise _reject(f"{case_id} reviewer verdict is invalid.")
    if len(ids) != len(set(ids)) or not all(isinstance(item, str) for item in ids):
        raise _reject(f"{case_id} selected hunk IDs are invalid.")
    if not set(cast(list[str], ids)).issubset(allowed_ids):
        raise _reject(f"{case_id} selected hunk IDs are not in the bound packet.")
    if verdict == "approved" and not ids:
        raise _reject(f"{case_id} approved mapping must select at least one hunk.")
    if verdict == "rejected" and ids:
        raise _reject(f"{case_id} rejected mapping cannot select hunks.")
    return value


def _decision_signature(value: dict[str, object]) -> tuple[object, tuple[str, ...]]:
    return value["verdict"], tuple(sorted(cast(list[str], value["selected_hunk_ids"])))


def _safe_patch_path(raw: bytes) -> str:
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _reject("Patch path is not UTF-8.") from exc
    raw_parts = value.split("/")
    path = PurePosixPath(value)
    if path.is_absolute() or not raw_parts or any(part in ("", ".", "..") for part in raw_parts):
        raise _reject("Patch path traversal is forbidden.")
    if "\\" in value or value.startswith("-"):
        raise _reject("Unsafe patch path is forbidden.")
    return value


def _reference(root: Path, path: Path) -> dict[str, object]:
    raw = _read_regular(path, _MAX_JSON_BYTES)
    return {
        "bytes": len(raw),
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _resolve_ref(root: Path, ref: dict[str, object]) -> Path:
    raw = ref.get("path")
    if not isinstance(raw, str):
        raise _reject("Artifact reference path is invalid.")
    safe = _safe_patch_path(raw.encode())
    candidate = root.joinpath(*PurePosixPath(safe).parts)
    resolved_root = root.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise _reject("Artifact reference escapes its private root.")
    return resolved


def _verify_ref(root: Path, ref: dict[str, object]) -> None:
    path = _resolve_ref(root, ref)
    raw = _read_regular(path, _MAX_JSON_BYTES)
    if len(raw) != ref.get("bytes") or hashlib.sha256(raw).hexdigest() != ref.get("sha256"):
        raise _reject("Artifact reference commitment is invalid.")


def _load_json(path: Path, limit: int) -> dict[str, object]:
    raw = _read_regular(path, limit)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _reject("Artifact is not valid JSON.") from exc
    return _dict(value, "JSON artifact")


def _read_regular(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise _reject("Artifact must be a regular non-symlink file.")
    size = path.stat().st_size
    if size < 1 or size > limit:
        raise _reject("Artifact exceeds its byte bound.")
    with path.open("rb") as handle:
        return handle.read(limit + 1)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _canonical_without(value: dict[str, object], key: str) -> bytes:
    return _canonical({name: item for name, item in value.items() if name != key})


def _self_hash(value: dict[str, object]) -> str:
    key = (
        "receipt_sha256"
        if "receipt_sha256" in value
        else "packet_sha256"
        if "packet_sha256" in value
        else "seal_sha256"
    )
    return hashlib.sha256(_canonical_without(value, key)).hexdigest()


def _dict(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise _reject(f"{label} must be an object.")
    return cast(dict[str, object], value)


def _exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise _reject(f"{label} has missing or unexpected fields.")


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise _reject("Timestamp must be RFC 3339 UTC.")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _reject("Timestamp must be RFC 3339 UTC.") from exc


def _case_id(value: str) -> None:
    if _CASE_ID.fullmatch(value) is None:
        raise _reject("Case ID is invalid.")


def _git_sha(value: str) -> None:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Tool Git SHA is invalid.")


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_mapping_packets", message)
