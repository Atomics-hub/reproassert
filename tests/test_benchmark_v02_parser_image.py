from __future__ import annotations

import hashlib
import io
import json
import subprocess
from pathlib import Path
from typing import ClassVar

import pytest
from click.testing import CliRunner

import reproassert.benchmark_v02_parser_image as parser_image
import reproassert.cli as cli_module
from reproassert.benchmark_v02_preparation import FROZEN_V02_DATASET_PARSER_IMAGE_ID
from reproassert.errors import PolicyRejection

EXPECTED_ID = FROZEN_V02_DATASET_PARSER_IMAGE_ID
REAL_DOCKER_ENGINE = parser_image._DockerEngine


class _FakeDocker:
    loaded: bytes | None = None
    inspected: str | None = None
    inspection: ClassVar[dict[str, object]] = {
        "Id": EXPECTED_ID,
        "Os": "linux",
        "Architecture": "arm64",
    }

    def load(self, archive: object, *, timeout_seconds: float) -> None:
        assert timeout_seconds == parser_image.DEFAULT_LOAD_TIMEOUT_SECONDS
        assert hasattr(archive, "read")
        type(self).loaded = archive.read()  # type: ignore[union-attr]

    def inspect(self, image_id: str) -> dict[str, object]:
        type(self).inspected = image_id
        return dict(type(self).inspection)


@pytest.fixture(autouse=True)
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeDocker.loaded = None
    _FakeDocker.inspected = None
    _FakeDocker.inspection = {
        "Id": EXPECTED_ID,
        "Os": "linux",
        "Architecture": "arm64",
    }
    monkeypatch.setattr(parser_image, "_DockerEngine", _FakeDocker)


def _install(archive: Path, **overrides: object) -> parser_image.InstalledParserImage:
    arguments: dict[str, object] = {
        "expected_archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "expected_image_id": EXPECTED_ID,
        "expected_platform": "linux/arm64",
    }
    arguments.update(overrides)
    return parser_image.install_v02_parser_image(archive, **arguments)  # type: ignore[arg-type]


def test_installer_hashes_and_loads_the_same_regular_archive(tmp_path: Path) -> None:
    archive = tmp_path / "parser-image.tar"
    archive.write_bytes(b"exact docker archive")

    result = _install(archive)

    assert result.archive_path == archive.resolve()
    assert result.archive_bytes == len(b"exact docker archive")
    assert result.archive_sha256 == hashlib.sha256(b"exact docker archive").hexdigest()
    assert result.image_id == EXPECTED_ID
    assert result.platform == "linux/arm64"
    assert _FakeDocker.loaded == b"exact docker archive"
    assert _FakeDocker.inspected == EXPECTED_ID


def test_installer_rejects_symlink_without_loading(tmp_path: Path) -> None:
    target = tmp_path / "target.tar"
    target.write_bytes(b"archive")
    archive = tmp_path / "parser-image.tar"
    archive.symlink_to(target)

    with pytest.raises(PolicyRejection, match="unsafe input path"):
        _install(archive)

    assert _FakeDocker.loaded is None


def test_installer_rejects_oversized_archive_without_loading(tmp_path: Path) -> None:
    archive = tmp_path / "parser-image.tar"
    archive.write_bytes(b"four")

    with pytest.raises(PolicyRejection, match="size limit"):
        _install(archive, max_archive_bytes=3)

    assert _FakeDocker.loaded is None


def test_installer_rejects_wrong_hash_without_loading(tmp_path: Path) -> None:
    archive = tmp_path / "parser-image.tar"
    archive.write_bytes(b"archive")

    with pytest.raises(PolicyRejection, match="SHA-256"):
        _install(archive, expected_archive_sha256="0" * 64)

    assert _FakeDocker.loaded is None


def test_installer_rejects_wrong_loaded_image_id(tmp_path: Path) -> None:
    archive = tmp_path / "parser-image.tar"
    archive.write_bytes(b"archive")
    _FakeDocker.inspection["Id"] = f"sha256:{'1' * 64}"

    with pytest.raises(PolicyRejection, match="exact frozen image ID"):
        _install(archive)


def test_installer_rejects_wrong_loaded_platform(tmp_path: Path) -> None:
    archive = tmp_path / "parser-image.tar"
    archive.write_bytes(b"archive")
    _FakeDocker.inspection["Architecture"] = "amd64"

    with pytest.raises(PolicyRejection, match="expected platform"):
        _install(archive)


def test_cli_installs_and_reports_verified_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "parser-image.tar"
    archive.write_bytes(b"archive")
    digest = hashlib.sha256(b"archive").hexdigest()
    monkeypatch.setattr(
        cli_module,
        "install_v02_parser_image",
        lambda *args, **kwargs: parser_image.InstalledParserImage(
            archive_path=archive.resolve(),
            archive_sha256=digest,
            archive_bytes=7,
            image_id=EXPECTED_ID,
            platform="linux/arm64",
        ),
    )

    result = CliRunner().invoke(
        cli_module.main,
        [
            "benchmark",
            "install-v02-parser-image",
            str(archive),
            "--archive-sha256",
            digest,
        ],
    )

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output == {
        "archive": str(archive.resolve()),
        "archive_bytes": 7,
        "archive_sha256": digest,
        "image_id": EXPECTED_ID,
        "platform": "linux/arm64",
        "verified": True,
    }


def test_real_engine_wrapper_loads_and_inspects_with_bounded_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    class FakeProcess:
        def __init__(self, args: list[str], **kwargs: object) -> None:
            calls.append(args)
            payload = (
                b"Loaded image\n"
                if args[2:] == ["image", "load"]
                else json.dumps(
                    [{"Id": EXPECTED_ID, "Os": "linux", "Architecture": "arm64"}]
                ).encode()
            )
            self.stdout = io.BytesIO(payload)

        def wait(self, timeout: float) -> int:
            assert timeout in {20.0, 30.0}
            return 0

    monkeypatch.setattr(parser_image.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(parser_image.subprocess, "Popen", FakeProcess)
    engine = REAL_DOCKER_ENGINE()
    engine.load(io.BytesIO(b"archive"), timeout_seconds=30.0)

    assert engine.inspect(EXPECTED_ID) == {
        "Id": EXPECTED_ID,
        "Os": "linux",
        "Architecture": "arm64",
    }
    assert calls == [
        ["/usr/bin/docker", "image", "load"],
        ["/usr/bin/docker", "image", "inspect", EXPECTED_ID],
    ]


def test_real_engine_wrapper_rejects_missing_docker_and_bad_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(parser_image.shutil, "which", lambda name: None)
    with pytest.raises(PolicyRejection, match="Docker CLI"):
        REAL_DOCKER_ENGINE()

    class BadProcess:
        stdout = io.BytesIO(b"not-json")

        def __init__(self, *args: object, **kwargs: object) -> None:
            self.stdout = io.BytesIO(b"not-json")

        def wait(self, timeout: float) -> int:
            return 0

    monkeypatch.setattr(parser_image.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(parser_image.subprocess, "Popen", BadProcess)
    with pytest.raises(PolicyRejection, match="invalid parser image inspection JSON"):
        REAL_DOCKER_ENGINE().inspect(EXPECTED_ID)


def test_real_engine_wrapper_kills_timed_out_command(monkeypatch: pytest.MonkeyPatch) -> None:
    class TimedOutProcess:
        stdout = io.BytesIO(b"")
        killed = False

        def __init__(self, *args: object, **kwargs: object) -> None:
            self.stdout = io.BytesIO(b"")
            self.waits = 0

        def wait(self, timeout: float) -> int:
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired("docker", timeout)
            return -9

        def kill(self) -> None:
            self.killed = True

    monkeypatch.setattr(parser_image.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(parser_image.subprocess, "Popen", TimedOutProcess)
    with pytest.raises(PolicyRejection, match="wall-clock"):
        REAL_DOCKER_ENGINE().load(io.BytesIO(b"archive"), timeout_seconds=1.0)
