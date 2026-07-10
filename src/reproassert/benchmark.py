from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

from reproassert.errors import PolicyRejection
from reproassert.safeio import sanitize_log

EVENT_SCHEMA_VERSION = "1.0.0"
BENCHMARK_VERSION = "0.1.0"
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_PUBLIC_EXCERPT_BYTES = 2_048

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}")
_CASE_ID = re.compile(r"rk-v0\.1-[0-9]{3}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RFC3339_UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z"
)
_SAFE_PROVIDER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
_SAFE_HOST = re.compile(r"[A-Za-z0-9.-]{1,253}")
_SAFE_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")
_SAFE_CLASSIFICATION = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,99}")
_CALL_ID = re.compile(r"call_[0-9a-f]{32}")
_OFFLINE_PROVIDERS = frozenset({"offline-fixture", "local-model"})
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"),
        r"\1<redacted>",
    ),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)"
            r"(\s*[=:]\s*)[^\s,;]+"
        ),
        r"\1\2<redacted>",
    ),
    (
        re.compile(r"\b(?:sk_|sk(?:-[A-Za-z0-9]+)*-|gh[pousr]_)[A-Za-z0-9_-]{8,}\b"),
        "<redacted-token>",
    ),
)
_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/(?:Users|home)/[^\s'\"]+"),
    re.compile(r"/(?:private/)?(?:tmp|var/folders)/[^\s'\"]+"),
    re.compile(r"[A-Za-z]:\\(?:Users|Temp)\\[^\s'\"]+"),
)


@dataclass(frozen=True)
class LedgerSnapshot:
    """A fully decoded, chain-checked view of one benchmark event ledger."""

    events: tuple[dict[str, Any], ...]
    encoded: bytes
    errors: tuple[str, ...]
    sha256: str
    head_event_sha256: str | None


@dataclass(frozen=True)
class _BenchmarkModelCallRecorder:
    """Persist provider-call lifecycle events under an atomic campaign spend guard."""

    ledger_path: Path
    lane: str
    batch_id: str
    attempt_id: str
    case_id: str
    model_identity: Mapping[str, object]
    pricing_snapshot_sha256: str
    reserved_worst_case_microusd: int
    max_case_attributable_microusd: int
    max_campaign_attributable_microusd: int
    spend_authorization_status: str
    spend_authorization_ref: str | None

    def __post_init__(self) -> None:
        ledger_path = Path(os.path.abspath(os.fspath(self.ledger_path)))
        object.__setattr__(self, "ledger_path", ledger_path)
        if self.lane not in {"smoke", "scored"}:
            raise PolicyRejection(
                "benchmark_event_lane", "Benchmark recorder lane must be smoke or scored."
            )
        _require_identifier(self.batch_id, "batch_id")
        _require_identifier(self.attempt_id, "attempt_id")
        if _CASE_ID.fullmatch(self.case_id) is None:
            raise PolicyRejection("benchmark_event_identity", "Invalid benchmark recorder case_id.")
        identity = _validated_model_identity(self.model_identity)
        object.__setattr__(self, "model_identity", MappingProxyType(identity))
        _require_sha256(self.pricing_snapshot_sha256, "pricing_snapshot_sha256")
        for name in (
            "reserved_worst_case_microusd",
            "max_case_attributable_microusd",
            "max_campaign_attributable_microusd",
        ):
            _require_nonnegative_int(getattr(self, name), name)
        if self.reserved_worst_case_microusd > self.max_case_attributable_microusd:
            raise PolicyRejection(
                "benchmark_spend_limit", "Model-call reservation exceeds the case spend cap."
            )
        if self.reserved_worst_case_microusd > self.max_campaign_attributable_microusd:
            raise PolicyRejection(
                "benchmark_spend_limit", "Model-call reservation exceeds the campaign spend cap."
            )
        if self.spend_authorization_status == "offline_zero_cost":
            if self.spend_authorization_ref is not None:
                raise PolicyRejection(
                    "benchmark_spend_authorization",
                    "Offline zero-cost authorization cannot cite a paid-spend approval.",
                )
        elif self.spend_authorization_status == "explicit_user_approval":
            if self.lane == "smoke":
                raise PolicyRejection(
                    "benchmark_spend_authorization",
                    "Public smoke is deterministic harness work and cannot use a paid provider.",
                )
            reference = self.spend_authorization_ref
            if (
                not isinstance(reference, str)
                or not 3 <= len(reference) <= 200
                or not reference.isprintable()
            ):
                raise PolicyRejection(
                    "benchmark_spend_authorization",
                    "Paid model use requires a bounded explicit authorization reference.",
                )
        else:
            raise PolicyRejection(
                "benchmark_spend_authorization",
                "Benchmark model calls require offline_zero_cost or explicit_user_approval.",
            )

    def model_call_started(self, event: Mapping[str, object]) -> None:
        """Validate, budget-check, append, and fsync before the provider request is sent."""

        payload = _validated_model_call_start(event)
        self._validate_current_authorization(payload)
        payload.update(
            {
                "model_identity": dict(self.model_identity),
                "pricing_snapshot_sha256": self.pricing_snapshot_sha256,
                "reserved_worst_case_microusd": self.reserved_worst_case_microusd,
            }
        )
        _append_event(
            self.ledger_path,
            lane=self.lane,
            batch_id=self.batch_id,
            attempt_id=self.attempt_id,
            case_id=self.case_id,
            event_type="model_call_started",
            payload=payload,
            _pre_append=lambda snapshot: self._preflight_model_start(snapshot, payload),
        )

    def model_call_finished(self, event: Mapping[str, object]) -> None:
        """Append exactly the bounded terminal payload emitted by the provider adapter."""

        payload = _validated_model_call_finish(event)
        _append_event(
            self.ledger_path,
            lane=self.lane,
            batch_id=self.batch_id,
            attempt_id=self.attempt_id,
            case_id=self.case_id,
            event_type="model_call_finished",
            payload=payload,
            _pre_append=lambda snapshot: self._preflight_model_finish(snapshot, payload),
        )

    def _validate_current_authorization(self, payload: Mapping[str, Any]) -> None:
        provider = payload["provider"]
        if self.lane == "smoke" and provider != "offline-fixture":
            raise PolicyRejection(
                "benchmark_model_lifecycle",
                "Public smoke permits only the deterministic offline fixture adapter.",
            )
        if self.spend_authorization_status == "offline_zero_cost":
            if provider not in _OFFLINE_PROVIDERS or self.reserved_worst_case_microusd != 0:
                raise PolicyRejection(
                    "benchmark_spend_authorization",
                    "Zero-cost mode permits only offline-fixture/local-model with zero reserve.",
                )
        elif provider not in _OFFLINE_PROVIDERS and self.reserved_worst_case_microusd == 0:
            raise PolicyRejection(
                "benchmark_spend_limit",
                "A paid provider call requires a positive worst-case spend reservation.",
            )

    def _preflight_model_start(self, snapshot: LedgerSnapshot, payload: Mapping[str, Any]) -> None:
        start_payload = self._matching_attempt_start(snapshot, payload)
        campaign = start_payload.get("campaign")
        wall_cap = campaign.get("max_case_wall_ms") if isinstance(campaign, Mapping) else None
        observed_ms = sum(
            event_payload.get("duration_ms", 0)
            for event in snapshot.events
            if event.get("batch_id") == self.batch_id
            and event.get("case_id") == self.case_id
            and event.get("event_type") == "phase_finished"
            for event_payload in [_event_payload(event)]
            if isinstance(event_payload.get("duration_ms"), int)
        )
        if isinstance(wall_cap, int) and observed_ms >= wall_cap:
            raise PolicyRejection(
                "benchmark_time_limit", "Case wall-time budget is exhausted before model call."
            )
        known_campaign, known_case = self._known_spend_and_closed_calls(snapshot, payload)
        if known_case + self.reserved_worst_case_microusd > self.max_case_attributable_microusd:
            raise PolicyRejection(
                "benchmark_spend_limit", "Known spend plus reserve exceeds the case spend cap."
            )
        if (
            known_campaign + self.reserved_worst_case_microusd
            > self.max_campaign_attributable_microusd
        ):
            raise PolicyRejection(
                "benchmark_spend_limit", "Known spend plus reserve exceeds the campaign spend cap."
            )

    def _preflight_model_finish(self, snapshot: LedgerSnapshot, payload: Mapping[str, Any]) -> None:
        self._matching_attempt_start(snapshot, payload)
        matching_starts = [
            event
            for event in snapshot.events
            if _is_current_attempt_event(event, self)
            and event.get("event_type") == "model_call_started"
            and _event_payload(event).get("call_id") == payload["call_id"]
        ]
        if len(matching_starts) != 1:
            raise PolicyRejection(
                "benchmark_model_lifecycle",
                "Model-call finish requires one matching durable start in this attempt.",
            )
        start_payload = _event_payload(matching_starts[0])
        if start_payload.get("started_at") != payload["started_at"]:
            raise PolicyRejection(
                "benchmark_model_lifecycle", "Model-call finish changed its start timestamp."
            )
        if (
            start_payload.get("model_identity") != dict(self.model_identity)
            or start_payload.get("pricing_snapshot_sha256") != self.pricing_snapshot_sha256
            or start_payload.get("reserved_worst_case_microusd")
            != self.reserved_worst_case_microusd
        ):
            raise PolicyRejection(
                "benchmark_campaign_freeze", "Model-call finish changed the recorder freeze."
            )
        if any(
            _is_current_attempt_event(event, self)
            and event.get("event_type") == "model_call_finished"
            and _event_payload(event).get("call_id") == payload["call_id"]
            for event in snapshot.events
        ):
            raise PolicyRejection(
                "benchmark_model_lifecycle", "Model-call finish is already recorded."
            )

    def _matching_attempt_start(
        self, snapshot: LedgerSnapshot, call_payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        for event in snapshot.events:
            if event.get("attempt_id") != self.attempt_id:
                continue
            if not _is_current_attempt_event(event, self):
                raise PolicyRejection(
                    "benchmark_model_lifecycle", "Benchmark attempt identity changed in the ledger."
                )
        starts = [
            event
            for event in snapshot.events
            if _is_current_attempt_event(event, self)
            and event.get("event_type") == "attempt_started"
        ]
        if len(starts) != 1:
            raise PolicyRejection(
                "benchmark_model_lifecycle",
                "Model calls require one matching durable attempt_started event.",
            )
        if any(
            _is_current_attempt_event(event, self) and event.get("event_type") == "attempt_finished"
            for event in snapshot.events
        ):
            raise PolicyRejection(
                "benchmark_model_lifecycle", "Cannot record a model call after attempt_finished."
            )
        start_payload = _event_payload(starts[0])
        campaign = start_payload.get("campaign")
        generator = start_payload.get("generator")
        authorization = (
            campaign.get("spend_authorization") if isinstance(campaign, Mapping) else None
        )
        generator_call_matches = True
        if "provider" in call_payload:
            generator_call_matches = (
                isinstance(generator, Mapping)
                and generator.get("provider") == call_payload.get("provider")
                and generator.get("requested_model") == call_payload.get("requested_model")
                and generator.get("model_identity") == dict(self.model_identity)
                and generator.get("config_sha256") == call_payload.get("config_sha256")
            )
        if (
            not isinstance(campaign, Mapping)
            or campaign.get("campaign_id") != self.batch_id
            or campaign.get("max_case_attributable_microusd") != self.max_case_attributable_microusd
            or campaign.get("max_campaign_attributable_microusd")
            != self.max_campaign_attributable_microusd
            or not isinstance(authorization, Mapping)
            or authorization.get("status") != self.spend_authorization_status
            or authorization.get("authorization_ref") != self.spend_authorization_ref
            or start_payload.get("pricing_snapshot_sha256") != self.pricing_snapshot_sha256
            or not generator_call_matches
        ):
            raise PolicyRejection(
                "benchmark_campaign_freeze",
                "Model call does not match the durable attempt and campaign freeze.",
            )
        return start_payload

    def _known_spend_and_closed_calls(
        self, snapshot: LedgerSnapshot, new_payload: Mapping[str, Any]
    ) -> tuple[int, int]:
        starts: dict[str, dict[str, Any]] = {}
        finishes: dict[str, list[dict[str, Any]]] = {}
        model_costs: dict[str, list[dict[str, Any]]] = {}
        known_campaign = 0
        known_case = 0

        for event in snapshot.events:
            if event.get("batch_id") != self.batch_id:
                continue
            event_type = event.get("event_type")
            event_payload = _event_payload(event)
            if event_type == "model_call_started":
                call_id = event_payload.get("call_id")
                if not isinstance(call_id, str) or call_id in starts:
                    raise PolicyRejection(
                        "benchmark_model_lifecycle", "Campaign model-call starts are ambiguous."
                    )
                starts[call_id] = event
            elif event_type == "model_call_finished":
                call_id = event_payload.get("call_id")
                if not isinstance(call_id, str):
                    raise PolicyRejection(
                        "benchmark_model_lifecycle", "Campaign model-call finish has no call_id."
                    )
                finishes.setdefault(call_id, []).append(event)
            elif event_type == "cost_recorded":
                amount = _known_cost_amount(event_payload)
                if event_payload.get("attribution") == "scored":
                    known_campaign += amount
                    if event.get("case_id") == self.case_id:
                        known_case += amount
                if event_payload.get("category") == "model_inference":
                    source_call_id = event_payload.get("source_call_id")
                    if not isinstance(source_call_id, str):
                        raise PolicyRejection(
                            "benchmark_spend_unknown", "Model cost is missing its source call."
                        )
                    model_costs.setdefault(source_call_id, []).append(event)

        new_call_id = new_payload["call_id"]
        if new_call_id in starts or new_call_id in finishes or new_call_id in model_costs:
            raise PolicyRejection(
                "benchmark_model_lifecycle", "Model call_id already exists in this campaign."
            )
        if any(event.get("case_id") == self.case_id for event in starts.values()):
            raise PolicyRejection(
                "benchmark_model_lifecycle", "Benchmark v0.1 permits one model call per case."
            )

        for call_id, start_event in starts.items():
            call_finishes = finishes.get(call_id, [])
            call_costs = model_costs.get(call_id, [])
            if len(call_finishes) != 1:
                raise PolicyRejection(
                    "benchmark_spend_unknown",
                    "A prior campaign model call is unmatched or ambiguously finished.",
                )
            usage = _event_payload(call_finishes[0]).get("usage")
            if not isinstance(usage, Mapping) or usage.get("status") == "unknown":
                raise PolicyRejection(
                    "benchmark_spend_unknown", "A prior campaign model call has unknown usage."
                )
            if len(call_costs) != 1:
                raise PolicyRejection(
                    "benchmark_spend_unknown",
                    "A prior campaign model call has missing or ambiguous cost.",
                )
            _known_cost_amount(_event_payload(call_costs[0]))
            if start_event.get("batch_id") != self.batch_id:
                raise PolicyRejection(
                    "benchmark_model_lifecycle", "Campaign model-call ownership changed."
                )
        if set(finishes) - set(starts) or set(model_costs) - set(starts):
            raise PolicyRejection(
                "benchmark_model_lifecycle", "Campaign has a finish or model cost without a start."
            )
        return known_campaign, known_case


def _validated_model_identity(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"status", "value"}:
        raise PolicyRejection(
            "benchmark_model_event", "Model identity must contain exactly status and value."
        )
    status = value.get("status")
    identity_value = value.get("value")
    if status not in {"reported", "alias_only", "unknown"}:
        raise PolicyRejection("benchmark_model_event", "Model identity status is invalid.")
    if status == "unknown":
        if identity_value is not None:
            raise PolicyRejection(
                "benchmark_model_event", "Unknown model identity must use a null value."
            )
    elif not isinstance(identity_value, str) or _SAFE_MODEL.fullmatch(identity_value) is None:
        raise PolicyRejection(
            "benchmark_model_event", "Known model identity must be a bounded identifier."
        )
    return {"status": status, "value": identity_value}


def _validated_model_call_start(event: Mapping[str, object]) -> dict[str, Any]:
    required = {
        "call_id",
        "started_at",
        "provider",
        "endpoint_host",
        "requested_model",
        "rendered_input_sha256",
        "config_sha256",
        "max_output_tokens",
    }
    payload = _exact_event_mapping(event, required, "model-call start")
    call_id = payload["call_id"]
    if not isinstance(call_id, str) or _CALL_ID.fullmatch(call_id) is None:
        raise PolicyRejection(
            "benchmark_model_event", "Model call_id is not bounded or unique-safe."
        )
    _require_timestamp(payload["started_at"], "started_at")
    provider = payload["provider"]
    if not isinstance(provider, str) or _SAFE_PROVIDER.fullmatch(provider) is None:
        raise PolicyRejection("benchmark_model_event", "Model provider is not privacy-safe.")
    endpoint_host = payload["endpoint_host"]
    if not isinstance(endpoint_host, str) or _SAFE_HOST.fullmatch(endpoint_host) is None:
        raise PolicyRejection("benchmark_model_event", "Model endpoint host is invalid.")
    requested_model = payload["requested_model"]
    if not isinstance(requested_model, str) or _SAFE_MODEL.fullmatch(requested_model) is None:
        raise PolicyRejection("benchmark_model_event", "Requested model is not privacy-safe.")
    _require_sha256(payload["rendered_input_sha256"], "rendered_input_sha256")
    _require_sha256(payload["config_sha256"], "config_sha256")
    max_output_tokens = payload["max_output_tokens"]
    if (
        isinstance(max_output_tokens, bool)
        or not isinstance(max_output_tokens, int)
        or not 1 <= max_output_tokens <= 2_147_483_647
    ):
        raise PolicyRejection("benchmark_model_event", "max_output_tokens is invalid.")
    return payload


def _validated_model_call_finish(event: Mapping[str, object]) -> dict[str, Any]:
    required = {
        "call_id",
        "status",
        "started_at",
        "completed_at",
        "duration_ms",
        "response_model",
        "response_id_sha256",
        "classification_code",
        "usage",
    }
    payload = _exact_event_mapping(event, required, "model-call finish")
    call_id = payload["call_id"]
    if not isinstance(call_id, str) or _CALL_ID.fullmatch(call_id) is None:
        raise PolicyRejection(
            "benchmark_model_event", "Model call_id is not bounded or unique-safe."
        )
    if payload["status"] not in {
        "succeeded",
        "provider_error",
        "timeout",
        "invalid_response",
        "refusal",
        "cancelled",
    }:
        raise PolicyRejection("benchmark_model_event", "Model-call terminal status is invalid.")
    started = _require_timestamp(payload["started_at"], "started_at")
    completed = _require_timestamp(payload["completed_at"], "completed_at")
    duration_ms = payload["duration_ms"]
    if isinstance(duration_ms, bool) or not isinstance(duration_ms, int) or duration_ms < 0:
        raise PolicyRejection("benchmark_model_event", "Model-call duration_ms is invalid.")
    elapsed_ms = (completed - started).total_seconds() * 1_000
    if completed < started or abs(elapsed_ms - duration_ms) > 1_000:
        raise PolicyRejection(
            "benchmark_model_event", "Model-call timestamps and duration are inconsistent."
        )
    response_model = payload["response_model"]
    if response_model is not None and (
        not isinstance(response_model, str) or _SAFE_MODEL.fullmatch(response_model) is None
    ):
        raise PolicyRejection("benchmark_model_event", "Response model is not privacy-safe.")
    response_id_sha256 = payload["response_id_sha256"]
    if response_id_sha256 is not None:
        _require_sha256(response_id_sha256, "response_id_sha256")
    classification = payload["classification_code"]
    if (
        not isinstance(classification, str)
        or _SAFE_CLASSIFICATION.fullmatch(classification) is None
    ):
        raise PolicyRejection("benchmark_model_event", "Model-call classification code is invalid.")
    usage = payload["usage"]
    if not isinstance(usage, Mapping):
        raise PolicyRejection("benchmark_model_event", "Model-call usage must be an object.")
    payload["usage"] = _validated_model_usage(usage)
    return payload


def _validated_model_usage(value: Mapping[str, object]) -> dict[str, object]:
    required = {
        "status",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "total_tokens",
    }
    usage = _exact_event_mapping(value, required, "model-call usage")
    status = usage["status"]
    names = ("input_tokens", "cached_input_tokens", "output_tokens", "total_tokens")
    values = [usage[name] for name in names]
    if status in {"reported", "estimated"}:
        if any(
            isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 2_147_483_647
            for count in values
        ):
            raise PolicyRejection(
                "benchmark_model_event", "Known model usage requires bounded integer counts."
            )
        input_tokens, cached_tokens, output_tokens, total_tokens = values
        if cached_tokens > input_tokens or total_tokens != input_tokens + output_tokens:
            raise PolicyRejection("benchmark_model_event", "Model usage arithmetic is invalid.")
    elif status == "unknown":
        if values != [None, None, None, None]:
            raise PolicyRejection(
                "benchmark_model_event", "Unknown model usage requires null counts."
            )
    elif status == "not_applicable":
        if values != [0, 0, 0, 0]:
            raise PolicyRejection(
                "benchmark_model_event", "Not-applicable model usage requires zero counts."
            )
    else:
        raise PolicyRejection("benchmark_model_event", "Model usage status is invalid.")
    return usage


def _exact_event_mapping(
    value: Mapping[str, object], required: set[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != required:
        raise PolicyRejection(
            "benchmark_model_event", f"Privacy-safe {label} fields do not match the contract."
        )
    return dict(value)


def _known_cost_amount(payload: Mapping[str, Any]) -> int:
    status = payload.get("status")
    amount = payload.get("amount_microusd")
    if status in {"unknown", "estimated"}:
        raise PolicyRejection(
            "benchmark_spend_unknown",
            "Campaign cost is unknown or estimated and cannot release its reservation.",
        )
    if status not in {"measured", "zero_verified"}:
        raise PolicyRejection("benchmark_spend_unknown", "Campaign cost status is invalid.")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        raise PolicyRejection("benchmark_spend_unknown", "Campaign cost amount is not known.")
    if status == "zero_verified" and amount != 0:
        raise PolicyRejection(
            "benchmark_spend_unknown", "Verified-zero campaign cost has a nonzero amount."
        )
    return amount


def _event_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        raise PolicyRejection(
            "benchmark_ledger_invalid", "Benchmark ledger event payload is not an object."
        )
    return payload


def _is_current_attempt_event(
    event: Mapping[str, Any], recorder: _BenchmarkModelCallRecorder
) -> bool:
    return (
        event.get("lane") == recorder.lane
        and event.get("batch_id") == recorder.batch_id
        and event.get("attempt_id") == recorder.attempt_id
        and event.get("case_id") == recorder.case_id
    )


def _require_sha256(value: object, name: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise PolicyRejection("benchmark_model_event", f"{name} must be one SHA-256 digest.")


def _require_nonnegative_int(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PolicyRejection("benchmark_spend_limit", f"{name} must be a non-negative integer.")


def _require_timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        raise PolicyRejection("benchmark_model_event", f"{name} must be an RFC 3339 UTC timestamp.")
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise PolicyRejection(
            "benchmark_model_event", f"{name} must be an RFC 3339 UTC timestamp."
        ) from exc


def canonical_json_bytes(value: object) -> bytes:
    """Return the single canonical JSON encoding used by public ledger hashes."""

    try:
        text = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise PolicyRejection(
            "benchmark_event_json", "Benchmark event is not bounded canonical JSON data."
        ) from exc
    return text.encode("ascii")


def event_sha256(event: dict[str, Any]) -> str:
    """Hash an event envelope while excluding its self-referential digest field."""

    unsigned = dict(event)
    unsigned.pop("event_sha256", None)
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def read_ledger(path: Path, *, expected_lane: str | None = None) -> LedgerSnapshot:
    """Read and validate a bounded regular JSONL event ledger without following a symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PolicyRejection(
            "benchmark_ledger_path", f"Cannot safely open benchmark ledger: {path}"
        ) from exc
    try:
        descriptor = os.fstat(fd)
        if not stat.S_ISREG(descriptor.st_mode):
            raise PolicyRejection(
                "benchmark_ledger_path", f"Benchmark ledger is not a regular file: {path}"
            )
        encoded = _read_bounded_fd(fd)
    finally:
        os.close(fd)
    return _decode_ledger_bytes(encoded, expected_lane=expected_lane)


def _append_event(
    path: Path,
    *,
    lane: str,
    batch_id: str,
    attempt_id: str,
    case_id: str,
    event_type: str,
    payload: dict[str, Any],
    recorded_at: str | None = None,
    _pre_append: Callable[[LedgerSnapshot], None] | None = None,
) -> dict[str, Any]:
    """Atomically append and fsync one hash-chained internal event.

    The caller must invoke this before the associated side effect for `attempt_started`,
    `phase_started`, and `model_call_started` events. A durable unmatched start is deliberate:
    the reducer then treats time and cost as unknown instead of silently assuming zero.
    This primitive is deliberately private: production callers use lifecycle-specific recorders
    so an invalid public event cannot be fsynced before schema and transition checks.
    """

    _require_identifier(batch_id, "batch_id")
    _require_identifier(attempt_id, "attempt_id")
    if _CASE_ID.fullmatch(case_id) is None:
        raise PolicyRejection("benchmark_event_identity", "Invalid benchmark case_id.")
    if lane not in {"smoke", "scored"}:
        raise PolicyRejection("benchmark_event_lane", "Benchmark lane must be smoke or scored.")
    if not isinstance(payload, dict):
        raise PolicyRejection(
            "benchmark_event_payload", "Benchmark event payload must be an object."
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise PolicyRejection(
            "benchmark_ledger_path", f"Cannot safely open benchmark ledger: {path}"
        ) from exc

    try:
        descriptor = os.fstat(fd)
        if not stat.S_ISREG(descriptor.st_mode):
            raise PolicyRejection(
                "benchmark_ledger_path", f"Benchmark ledger is not a regular file: {path}"
            )
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, os.SEEK_SET)
        snapshot = _decode_ledger_bytes(_read_bounded_fd(fd), expected_lane=lane)
        if snapshot.errors:
            detail = "; ".join(snapshot.errors[:3])
            raise PolicyRejection(
                "benchmark_ledger_invalid", f"Refusing to append to an invalid ledger: {detail}"
            )
        if _pre_append is not None:
            _pre_append(snapshot)

        timestamp = recorded_at or utc_now_text()
        if _RFC3339_UTC.fullmatch(timestamp) is None:
            raise PolicyRejection(
                "benchmark_event_time", "recorded_at must be an RFC 3339 UTC timestamp."
            )
        event: dict[str, Any] = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "benchmark_version": BENCHMARK_VERSION,
            "lane": lane,
            "sequence": len(snapshot.events) + 1,
            "recorded_at": timestamp,
            "previous_event_sha256": snapshot.head_event_sha256,
            "batch_id": batch_id,
            "attempt_id": attempt_id,
            "case_id": case_id,
            "event_type": event_type,
            "payload": payload,
        }
        event["event_sha256"] = event_sha256(event)
        encoded_line = canonical_json_bytes(event) + b"\n"
        if len(snapshot.encoded) + len(encoded_line) > MAX_LEDGER_BYTES:
            raise PolicyRejection(
                "benchmark_ledger_limit", "Benchmark ledger would exceed its 32 MiB limit."
            )
        _write_all(fd, encoded_line)
        os.fsync(fd)
        return event
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def is_exact_prefix(previous: bytes, current: bytes) -> bool:
    """Return whether protected-history ledger bytes are an exact prefix of current bytes."""

    return len(previous) <= len(current) and current.startswith(previous)


def sanitize_public_excerpt(text: str) -> dict[str, object]:
    """Create the only bounded log representation permitted in a public benchmark event."""

    captured_bytes = len(text.encode("utf-8", errors="replace"))
    sanitized = sanitize_log(text)
    for pattern, replacement in _SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    for pattern in _PATH_PATTERNS:
        sanitized = pattern.sub("<host-path>", sanitized)
    excerpt, truncated = _truncate_utf8(sanitized, MAX_PUBLIC_EXCERPT_BYTES)
    encoded_excerpt = excerpt.encode("utf-8")
    return {
        "policy": "redacted_excerpt_v1",
        "captured_bytes": captured_bytes,
        "excerpt_bytes": len(encoded_excerpt),
        "truncated": truncated,
        "excerpt_sha256": hashlib.sha256(encoded_excerpt).hexdigest(),
        "excerpt": excerpt,
    }


def _decode_ledger_bytes(encoded: bytes, *, expected_lane: str | None) -> LedgerSnapshot:
    errors: list[str] = []
    events: list[dict[str, Any]] = []
    if len(encoded) > MAX_LEDGER_BYTES:
        errors.append("ledger exceeds 32 MiB")
    if encoded and not encoded.endswith(b"\n"):
        errors.append("ledger must end with a newline")

    previous_hash: str | None = None
    for line_number, raw_line in enumerate(encoded.splitlines(), start=1):
        label = f"line {line_number}"
        if not raw_line:
            errors.append(f"{label}: blank ledger rows are forbidden")
            continue
        try:
            decoded = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            errors.append(f"{label}: invalid JSON: {exc}")
            continue
        if not isinstance(decoded, dict):
            errors.append(f"{label}: event must be an object")
            continue
        event = decoded
        events.append(event)
        try:
            if canonical_json_bytes(event) != raw_line:
                errors.append(f"{label}: event is not canonical JSON")
        except PolicyRejection as exc:
            errors.append(f"{label}: {exc}")
            continue

        expected_sequence = len(events)
        if event.get("sequence") != expected_sequence:
            errors.append(f"{label}: sequence must be {expected_sequence}")
        if event.get("schema_version") != EVENT_SCHEMA_VERSION:
            errors.append(f"{label}: unexpected schema_version")
        if event.get("benchmark_version") != BENCHMARK_VERSION:
            errors.append(f"{label}: unexpected benchmark_version")
        lane = event.get("lane")
        if lane not in {"smoke", "scored"}:
            errors.append(f"{label}: invalid lane")
        if expected_lane is not None and lane != expected_lane:
            errors.append(f"{label}: event lane does not match ledger lane {expected_lane}")
        if event.get("previous_event_sha256") != previous_hash:
            errors.append(f"{label}: previous_event_sha256 does not match chain head")
        digest = event.get("event_sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            errors.append(f"{label}: invalid event_sha256")
        elif digest != event_sha256(event):
            errors.append(f"{label}: event_sha256 does not match canonical event")
        else:
            previous_hash = digest

    return LedgerSnapshot(
        events=tuple(events),
        encoded=encoded,
        errors=tuple(errors),
        sha256=hashlib.sha256(encoded).hexdigest(),
        head_event_sha256=previous_hash,
    )


def _read_bounded_fd(fd: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(64 * 1024, MAX_LEDGER_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_LEDGER_BYTES:
            raise PolicyRejection(
                "benchmark_ledger_limit", "Benchmark ledger exceeds its 32 MiB limit."
            )
    return b"".join(chunks)


def _write_all(fd: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(fd, content[offset:])
        if written <= 0:
            raise OSError("short write while appending benchmark event")
        offset += written


def _require_identifier(value: str, name: str) -> None:
    if _IDENTIFIER.fullmatch(value) is None:
        raise PolicyRejection("benchmark_event_identity", f"Invalid benchmark {name}.")


def _truncate_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    marker = b"\n[excerpt truncated]"
    budget = max(0, max_bytes - len(marker))
    prefix = encoded[:budget]
    while prefix:
        try:
            decoded = prefix.decode("utf-8")
            break
        except UnicodeDecodeError:
            prefix = prefix[:-1]
    else:
        decoded = ""
    return decoded + marker.decode("ascii"), True
