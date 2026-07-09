# Release process

ReproAssert releases are deliberately tag-driven. A matching stable version tag runs the full quality, type, benchmark-contract, unit, coverage, and package checks before GitHub creates a release. The workflow produces a wheel and source distribution and records GitHub artifact attestations for both.

The workflow does **not** publish to PyPI. Publishing requires a separately reviewed PyPI project, GitHub trusted-publisher configuration scoped to this repository and release workflow, and explicit maintainer approval. Do not add an API token or broad package credential to repository secrets as a shortcut.

## Before tagging

1. Confirm `main` is clean, reviewed, and green on every supported Python version.
2. Update the version in `pyproject.toml` and `src/reproassert/__init__.py`; both must match.
3. Move relevant entries from `Unreleased` to a dated `X.Y.Z` changelog heading and add comparison links.
4. Run the local release checks from a clean environment:

   ```console
   uv sync --frozen --all-extras
   uv run --frozen --no-sync ruff check .
   uv run --frozen --no-sync ruff format --check .
   uv run --frozen --no-sync mypy src
   uv run --frozen --no-sync python scripts/validate_benchmark.py
   uv run --frozen --no-sync python -m pytest --cov=reproassert --cov-report=term-missing
   uv build --no-build-isolation
   ```

5. Install the wheel from `dist/` in a new virtual environment and run `reproassert --version`, `reproassert --help`, `reproassert schema`, and `reproassert doctor` on a Docker-capable machine.
6. Review the source distribution and wheel contents. Confirm the embedded sandbox `Dockerfile`, hash-locked requirements, and report schema are present; confirm the source distribution's shipped unit tests run; and confirm neither archive contains credentials, local reports, benchmark evaluator material, or unrelated files.

## Tag and publish the GitHub release

Create an annotated tag only after the commit has passed required CI. Sign it when the publishing maintainer has a configured signing identity. The workflow rejects prerelease-shaped tags, tags not contained by `main`, and any mismatch among the tag, package metadata, controller source, or built wheel. GitHub currently does not make a local tag signature part of the workflow's evidence; do not describe the release as signature-verified unless GitHub displays that verification.

```console
git tag -a vX.Y.Z -m "ReproAssert vX.Y.Z"
git push origin vX.Y.Z
```

Pushing the tag is the release authorization. A read-only verification job reruns locked Python checks, the Docker boundary, and the site contract. A separate read-only job builds with the checked-in uv lock and pinned setuptools backend, then uploads the distributions. Only a no-checkout attestation job receives job-scoped OIDC and attestation permissions; only after attestation passes does a no-checkout publishing job receive `contents: write`. Immediately before publication that job peels the current remote tag through GitHub's API and refuses the release unless it still resolves to the initiating `GITHUB_SHA`. The repository must also keep matching tag rules and immutable releases enabled; this workflow check narrows but does not replace those server-side controls. The workflow does not run on pull requests, does not use `pull_request_target`, use dependency caches in privileged jobs, or receive package registry credentials.

After completion:

1. Download and install the GitHub release wheel in a fresh environment.
2. Verify the release checksums and provenance with GitHub CLI:

   ```console
   sha256sum --check SHA256SUMS
   gh attestation verify reproassert-X.Y.Z-py3-none-any.whl --repo Atomics-hub/reproassert
   gh attestation verify reproassert-X.Y.Z.tar.gz --repo Atomics-hub/reproassert
   ```

3. Run the documented quickstart and Docker sandbox doctor from the installed artifact.
4. Confirm the GitHub release notes make no benchmark, security, or maintainer-validation claim beyond checked evidence.

If a release is wrong, publish a corrected patch release. Do not move or overwrite the public tag and do not replace assets under the same version.
