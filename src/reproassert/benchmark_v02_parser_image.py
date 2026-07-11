"""Fail-closed installation of the frozen benchmark v0.2 parser image."""

from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, cast

from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file

MAX_PARSER_IMAGE_ARCHIVE_BYTES = 512 * 1024 * 1024
DEFAULT_LOAD_TIMEOUT_SECONDS = 180.0
_MAX_DOCKER_OUTPUT_BYTES = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PLATFORM = re.compile(r"linux/(amd64|arm64)\Z")


@dataclass(frozen=True)
class InstalledParserImage:
    """Verified result of loading an exact parser-image archive."""

    archive_path: Path
    archive_sha256: str
    archive_bytes: int
    image_id: str
    platform: str


def install_v02_parser_image(
    archive_path: Path,
    *,
    expected_archive_sha256: str,
    expected_image_id: str,
    expected_platform: str,
    max_archive_bytes: int = MAX_PARSER_IMAGE_ARCHIVE_BYTES,
    timeout_seconds: float = DEFAULT_LOAD_TIMEOUT_SECONDS,
) -> InstalledParserImage:
    """Verify and load one exact Docker archive, then inspect its immutable identity.

    The archive is opened without following symlinks and copied into a private
    temporary file while hashing. Docker receives only those verified bytes. No
    tag is accepted as image identity.
    """

    archive = Path(archive_path)
    digest = _sha256(expected_archive_sha256, "archive SHA-256")
    image_id = _image_id(expected_image_id)
    platform = _platform(expected_platform)
    _bounded_positive_int(max_archive_bytes, "max_archive_bytes")
    _bounded_timeout(timeout_seconds)

    with open_regular_file(archive) as source, tempfile.TemporaryFile(mode="w+b") as verified:
        announced_size = source.seek(0, 2)
        if announced_size < 1:
            raise _reject("Parser image archive is empty.")
        if announced_size > max_archive_bytes:
            raise _reject("Parser image archive exceeds the configured size limit.")
        source.seek(0)
        actual_digest, size = _spool_and_hash(source, verified, max_archive_bytes)
        if size != announced_size:
            raise _reject("Parser image archive changed while it was being verified.")
        if actual_digest != digest:
            raise _reject("Parser image archive SHA-256 does not match the frozen value.")
        verified.seek(0)
        engine = _DockerEngine()
        engine.load(verified, timeout_seconds=float(timeout_seconds))

    inspection = engine.inspect(image_id)
    actual_id = inspection.get("Id")
    actual_os = inspection.get("Os")
    actual_architecture = inspection.get("Architecture")
    actual_platform = (
        f"{actual_os}/{actual_architecture}"
        if isinstance(actual_os, str) and isinstance(actual_architecture, str)
        else None
    )
    if actual_id != image_id:
        raise _reject("Loaded parser image does not have the exact frozen image ID.")
    if actual_platform != platform:
        raise _reject("Loaded parser image does not have the expected platform.")
    return InstalledParserImage(
        archive_path=archive.resolve(strict=True),
        archive_sha256=actual_digest,
        archive_bytes=size,
        image_id=image_id,
        platform=platform,
    )


class _DockerEngine:
    def __init__(self) -> None:
        docker = shutil.which("docker")
        if docker is None:
            raise _reject("Docker CLI is required to install the parser image.")
        self._docker = docker

    def load(self, archive: BinaryIO, *, timeout_seconds: float) -> None:
        result = self._run(
            ["image", "load"], timeout_seconds=timeout_seconds, stdin=archive
        )
        if result.returncode != 0:
            raise _reject("Docker could not load the verified parser image archive.")

    def inspect(self, image_id: str) -> dict[str, Any]:
        result = self._run(["image", "inspect", image_id], timeout_seconds=20.0)
        if result.returncode != 0:
            raise _reject("Docker could not inspect the loaded parser image.")
        try:
            root = json.loads(result.output.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _reject("Docker returned invalid parser image inspection JSON.") from exc
        if not isinstance(root, list) or len(root) != 1 or not isinstance(root[0], dict):
            raise _reject("Docker returned invalid parser image inspection evidence.")
        return cast(dict[str, Any], root[0])

    def _run(
        self,
        args: list[str],
        *,
        timeout_seconds: float,
        stdin: BinaryIO | None = None,
    ) -> _DockerResult:
        process = subprocess.Popen(
            [self._docker, *args],
            stdin=stdin if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
            },
        )
        output = bytearray()
        overflow = threading.Event()

        def read_output() -> None:
            if process.stdout is None:
                return
            while chunk := process.stdout.read(8192):
                remaining = _MAX_DOCKER_OUTPUT_BYTES - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()

        reader = threading.Thread(
            target=read_output, name="parser-image-docker-output", daemon=True
        )
        reader.start()
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=5)
            reader.join(timeout=2)
            raise _reject("Docker parser image command exceeded its wall-clock limit.") from exc
        reader.join(timeout=2)
        if overflow.is_set():
            raise _reject("Docker parser image command exceeded its output limit.")
        return _DockerResult(returncode=returncode, output=bytes(output))


@dataclass(frozen=True)
class _DockerResult:
    returncode: int
    output: bytes


def _spool_and_hash(source: BinaryIO, destination: BinaryIO, maximum: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    for chunk in iter(lambda: source.read(64 * 1024), b""):
        total += len(chunk)
        if total > maximum:
            raise _reject("Parser image archive exceeds the configured size limit.")
        digest.update(chunk)
        destination.write(chunk)
    destination.flush()
    return digest.hexdigest(), total


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be an exact lowercase SHA-256")
    return value


def _image_id(value: object) -> str:
    if not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None:
        raise ValueError("expected_image_id must be an exact immutable sha256 image ID")
    return value


def _platform(value: object) -> str:
    if not isinstance(value, str) or _PLATFORM.fullmatch(value) is None:
        raise ValueError("expected_platform must be linux/amd64 or linux/arm64")
    return value


def _bounded_positive_int(value: object, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 2 * 1024**3:
        raise ValueError(f"{label} must be an integer between 1 and 2147483648")


def _bounded_timeout(value: object) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 1 <= float(value) <= 600
    ):
        raise ValueError("timeout_seconds must be finite and between 1 and 600")


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_parser_image", message)
