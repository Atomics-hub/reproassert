from __future__ import annotations

from pathlib import Path


def test_pypi_publish_job_is_oidc_only_and_attestation_gated() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "release.yml").read_text()
    pypi_job = workflow.split("\n  pypi:\n", 1)[1].split("\n  publish:\n", 1)[0]
    github_publish_job = workflow.split("\n  publish:\n", 1)[1]

    assert "needs: [attest, resolve]" in pypi_job
    assert "name: pypi" in pypi_job
    assert "id-token: write" in pypi_job
    assert "actions/checkout" not in pypi_job
    assert "${{ secrets." not in pypi_job
    assert "password:" not in pypi_job
    assert "api-token" not in pypi_job
    assert "sha256sum --check SHA256SUMS" in pypi_job
    assert "cp release-dist/*.whl release-dist/*.tar.gz pypi-dist/" in pypi_job
    assert "pypa/gh-action-pypi-publish@cef221092ed1bacb1cc03d23a2d87d1d172e277b" in pypi_job
    assert "needs: [attest, pypi, resolve]" in github_publish_job


def test_release_workflow_has_no_broad_trigger_or_pypi_credential() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "release.yml").read_text()

    assert "pull_request_target" not in workflow
    assert "PYPI_API_TOKEN" not in workflow
    assert "pypi-token" not in workflow
