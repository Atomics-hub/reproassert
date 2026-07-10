from __future__ import annotations

import hashlib
from typing import Literal

from reproassert.dependency_prep import PYPI_INDEX_URL

DependencyPhase = Literal["download", "install"]

_ENVIRONMENT = (
    "HOME=/tmp/home",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "PATH=/usr/local/bin:/usr/bin:/bin",
    "PIP_CONFIG_FILE=/dev/null",
    "PIP_DISABLE_PIP_VERSION_CHECK=1",
    "PIP_NO_INPUT=1",
    "PIP_NO_PYTHON_VERSION_WARNING=1",
    "PYTHONDONTWRITEBYTECODE=1",
    "PYTHONHASHSEED=0",
    "TZ=UTC",
)


def dependency_phase_command(phase: DependencyPhase) -> tuple[str, ...]:
    """Return the complete trusted argv after the immutable image reference."""

    common = (
        "-i",
        *_ENVIRONMENT,
        "/usr/local/bin/python",
        "-I",
        "-m",
        "pip",
        "--isolated",
    )
    if phase == "download":
        return (
            *common,
            "download",
            "--disable-pip-version-check",
            "--no-input",
            "--no-cache-dir",
            "--keyring-provider",
            "disabled",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "--index-url",
            PYPI_INDEX_URL,
            "--dest",
            "/wheelhouse",
            "--requirement",
            "/input/requirements.lock",
        )
    if phase == "install":
        return (
            *common,
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-cache-dir",
            "--keyring-provider",
            "disabled",
            "--no-index",
            "--find-links=/wheelhouse",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "--no-compile",
            "--target",
            "/dependencies",
            "--requirement",
            "/input/requirements.lock",
        )
    raise ValueError(f"Unsupported dependency phase: {phase}")


def dependency_phase_command_sha256(phase: DependencyPhase) -> str:
    return hashlib.sha256("\0".join(dependency_phase_command(phase)).encode("utf-8")).hexdigest()
