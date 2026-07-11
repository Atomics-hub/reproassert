"""Strict allowlist for frozen SWE-bench instance-image runtimes."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file

INSTANCE_RUNTIME_SCHEMA_VERSION = "0.1.0"
INSTANCE_RUNTIME_ALGORITHM = "reproassert-swebench-instance-runtime-manifest-v1"
INSTANCE_RUNTIME_PROFILE = "swebench-instance-image-v1"
OFFICIAL_HARNESS_REPOSITORY = "https://github.com/SWE-bench/SWE-bench"
MAX_INSTANCE_RUNTIME_MANIFEST_BYTES = 256 * 1024
MAX_INSTANCE_RUNTIME_ENTRIES = 20

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IMAGE_TAG = re.compile(r"[a-z0-9][a-z0-9._/-]{0,199}:[A-Za-z0-9._-]{1,64}\Z")
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_INSTANCE_ID = re.compile(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[0-9]+\Z")
_ROOT_KEYS = {"algorithm", "entries", "harness", "manifest_sha256", "policy", "schema_version"}
_HARNESS_KEYS = {"git_sha", "repository", "specs_sha256"}
_ENTRY_KEYS = {
    "base_sha",
    "base_tree_oid",
    "case_id",
    "image_digest",
    "image_id",
    "image_tag",
    "instance_id",
    "spec_sha256",
}
_POLICY = {
    "capabilities": "drop_all",
    "commands": "reproassert-controller-allowlist-v1",
    "credentials": "none",
    "docker_socket": False,
    "host_bind_mounts": False,
    "network_mode": "none",
    "no_new_privileges": True,
    "platform": "linux/amd64",
    "profile": INSTANCE_RUNTIME_PROFILE,
    "resource_limits": "reproassert-sandbox-policy-v1",
}


@dataclass(frozen=True)
class InstanceRuntime:
    case_id: str
    instance_id: str
    base_sha: str
    base_tree_oid: str
    spec_sha256: str
    image_tag: str
    image_digest: str
    image_id: str


@dataclass(frozen=True)
class InstanceRuntimeManifest:
    harness_git_sha: str
    harness_specs_sha256: str
    entries: tuple[InstanceRuntime, ...]
    sha256: str

    def require(
        self,
        *,
        case_id: str,
        instance_id: str,
        image_tag: str,
        observed_image_digest: str,
        observed_image_id: str,
        observed_platform: str,
    ) -> InstanceRuntime:
        """Resolve one case and prove the local image is the frozen published image."""

        matches = tuple(
            entry
            for entry in self.entries
            if entry.case_id == case_id
            and entry.instance_id == instance_id
            and entry.image_tag == image_tag
        )
        if len(matches) != 1:
            raise _reject("Case does not select exactly one trusted instance runtime.")
        selected = matches[0]
        if selected.image_digest != observed_image_digest:
            raise _reject("Instance image tag does not resolve to its frozen repository digest.")
        if selected.image_id != observed_image_id:
            raise _reject("Loaded instance image does not have its frozen image ID.")
        if observed_platform != _POLICY["platform"]:
            raise _reject("Instance image platform is not the frozen linux/amd64 platform.")
        return selected


def load_instance_runtime_manifest(path: Path) -> InstanceRuntimeManifest:
    """Load canonical, duplicate-free, self-hashed instance runtime evidence."""

    with open_regular_file(Path(path)) as stream:
        encoded = stream.read(MAX_INSTANCE_RUNTIME_MANIFEST_BYTES + 1)
    if len(encoded) > MAX_INSTANCE_RUNTIME_MANIFEST_BYTES:
        raise _reject("Instance runtime manifest exceeds the size limit.")
    try:
        value = json.loads(
            encoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("Instance runtime manifest is invalid JSON.") from exc
    if not isinstance(value, Mapping) or encoded != _canonical(value) + b"\n":
        raise _reject("Instance runtime manifest is not canonical JSON.")
    root = _exact(value, _ROOT_KEYS, "instance runtime manifest")
    if (
        root["schema_version"] != INSTANCE_RUNTIME_SCHEMA_VERSION
        or root["algorithm"] != INSTANCE_RUNTIME_ALGORITHM
    ):
        raise _reject("Instance runtime manifest identity is unsupported.")
    manifest_sha256 = _digest(root["manifest_sha256"], "manifest")
    if manifest_sha256 != _self_hash(root):
        raise _reject("Instance runtime manifest digest is invalid.")

    policy = _exact(root["policy"], set(_POLICY), "instance runtime policy")
    if policy != _POLICY:
        raise _reject("Instance runtime policy differs from the trusted execution profile.")
    harness = _exact(root["harness"], _HARNESS_KEYS, "instance runtime harness")
    if harness["repository"] != OFFICIAL_HARNESS_REPOSITORY:
        raise _reject("Instance runtime harness is not the frozen official repository.")
    harness_git_sha = _text(harness["git_sha"], _GIT_SHA, "harness Git SHA")
    harness_specs_sha256 = _digest(harness["specs_sha256"], "harness specs")

    raw_entries = root["entries"]
    if (
        not isinstance(raw_entries, list)
        or not 1 <= len(raw_entries) <= MAX_INSTANCE_RUNTIME_ENTRIES
    ):
        raise _reject("Instance runtime entry count is invalid.")
    entries: list[InstanceRuntime] = []
    for position, raw_entry in enumerate(raw_entries, start=1):
        entry = _exact(raw_entry, _ENTRY_KEYS, f"instance runtime entry {position}")
        entries.append(
            InstanceRuntime(
                case_id=_text(entry["case_id"], _CASE_ID, "case ID"),
                instance_id=_text(entry["instance_id"], _INSTANCE_ID, "instance ID"),
                base_sha=_text(entry["base_sha"], _GIT_SHA, "base SHA"),
                base_tree_oid=_text(entry["base_tree_oid"], _GIT_SHA, "base tree OID"),
                spec_sha256=_digest(entry["spec_sha256"], "instance spec"),
                image_tag=_text(entry["image_tag"], _IMAGE_TAG, "instance image tag"),
                image_digest=_text(entry["image_digest"], _IMAGE_ID, "instance image digest"),
                image_id=_text(entry["image_id"], _IMAGE_ID, "instance image ID"),
            )
        )
    if entries != sorted(entries, key=lambda entry: entry.case_id):
        raise _reject("Instance runtime entries are not canonically ordered by case ID.")
    if len({entry.case_id for entry in entries}) != len(entries) or len(
        {entry.instance_id for entry in entries}
    ) != len(entries):
        raise _reject("Instance runtime manifest contains an ambiguous case or instance.")
    return InstanceRuntimeManifest(
        harness_git_sha=harness_git_sha,
        harness_specs_sha256=harness_specs_sha256,
        entries=tuple(entries),
        sha256=manifest_sha256,
    )


def instance_runtime_manifest_bytes(
    *,
    harness_git_sha: str,
    harness_specs_sha256: str,
    entries: tuple[InstanceRuntime, ...],
) -> bytes:
    """Render the manifest only after all exact image identities are known."""

    root: dict[str, object] = {
        "algorithm": INSTANCE_RUNTIME_ALGORITHM,
        "entries": [
            {
                "base_sha": entry.base_sha,
                "base_tree_oid": entry.base_tree_oid,
                "case_id": entry.case_id,
                "image_digest": entry.image_digest,
                "image_id": entry.image_id,
                "image_tag": entry.image_tag,
                "instance_id": entry.instance_id,
                "spec_sha256": entry.spec_sha256,
            }
            for entry in sorted(entries, key=lambda entry: entry.case_id)
        ],
        "harness": {
            "git_sha": harness_git_sha,
            "repository": OFFICIAL_HARNESS_REPOSITORY,
            "specs_sha256": harness_specs_sha256,
        },
        "manifest_sha256": "0" * 64,
        "policy": dict(_POLICY),
        "schema_version": INSTANCE_RUNTIME_SCHEMA_VERSION,
    }
    root["manifest_sha256"] = _self_hash(root)
    return _canonical(root) + b"\n"


def _self_hash(root: Mapping[str, object]) -> str:
    payload = dict(root)
    payload["manifest_sha256"] = "0" * 64
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != keys
        or not all(isinstance(key, str) for key in value)
    ):
        raise _reject(f"{label.capitalize()} fields are invalid.")
    return cast(dict[str, object], dict(value))


def _text(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not value.isascii() or pattern.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} is invalid.")
    return value


def _digest(value: object, label: str) -> str:
    return _text(value, _SHA256, f"{label} SHA-256")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise ValueError("non-finite number")


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_instance_runtime", message)
