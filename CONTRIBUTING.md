# Contributing to ReproAssert

ReproAssert is a proof-first security tool. A small change to intake, candidate policy, Docker arguments, result classification, or report parsing can change what the product is allowed to claim. Keep changes narrow, test the failure path, and preserve the boundary between evidence and conclusions.

By participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Requirements:

- Python 3.10 or newer;
- [uv](https://docs.astral.sh/uv/); and
- Docker Engine or Docker Desktop for the opt-in integration test.

```console
git clone https://github.com/Atomics-hub/reproassert.git
cd reproassert
uv sync --extra dev
```

Inspect the CLI before changing its contract:

```console
uv run reproassert --help
uv run reproassert issue --help
uv run reproassert replay --help
```

Build and inspect the strict runner when working on sandbox behavior:

```console
uv run reproassert sandbox build
uv run reproassert doctor
```

## Required checks

Run the fast suite while iterating:

```console
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
uv run python scripts/validate_benchmark.py
```

Before requesting review, run coverage and package construction as well:

```console
uv run pytest --cov=reproassert --cov-report=term-missing
uv build
```

The coverage floor is defined in `pyproject.toml`; do not lower it to make a change pass. To exercise the real Docker boundary after building the image:

```console
REPROASSERT_RUN_DOCKER_TESTS=1 \
  uv run pytest tests/integration/test_docker_sandbox.py -q
```

### CI budget

GitHub Actions is the final independent check, not the development loop. Before opening or updating
a pull request, run the relevant commands above locally and batch a coherent, reviewable change.
Do not push speculative fixes one at a time, restart a cancelled run, or use “re-run failed jobs” to
hide a nondeterministic failure. Diagnose the first failure locally, add a regression test when the
cause is in ReproAssert, then push one corrective update.

New workflows, triggers, matrix entries, service containers, artifact uploads, or scheduled jobs
must state their expected runner-minute and storage impact in the pull request. Prefer extending an
existing bounded job when it preserves fault isolation. Paid model calls, hosted runners, and other
metered services are never an implicit CI dependency; they require a separate explicit budget and a
deny-by-default gate.

## Change rules

### Preserve the trust boundary

- Treat issue text, repository content, dependencies, candidate code, test output, JUnit XML, and reports as untrusted.
- Never add a native host-execution fallback for repository code.
- Do not mount the Docker socket, SSH agent, credentials, browser state, proxy environment, or unrelated host paths into verification.
- Generator adapters are user-trusted controller processes. Pass secrets only through explicit `--pass-env` names, never fixtures, reports, logs, or source context.
- New command execution must use controller-owned structured arguments, not issue text, report text, or a shell string.

Read [the security model](docs/security-model.md), [threat model](docs/threat-model.md), and [sandbox profiles](docs/sandbox-profiles.md) before changing these surfaces.

### Preserve the claim ceiling

The current workflow may claim at most `repeatable_base_failure`. It does not execute a fixed revision, establish semantic correctness, or record maintainer acceptance.

Any change to claim names, acceptance logic, failure taxonomy, rerun count, fingerprint normalization, or report evidence requires:

1. focused unit and adversarial regression tests;
2. an update to [architecture](docs/architecture.md);
3. an update to [evaluation](docs/evaluation.md) when benchmark semantics change; and
4. a new decision record when the public contract changes materially.

### Keep the generator protocol strict

Protocol v1 accepts exactly `test_content`, `expected_symptom`, and `rationale`. Extra fields, command fields, free-form logs, and unbounded output are rejected. An adapter example belongs in `examples/`; provider credentials do not.

### Keep benchmark evaluation blinded

The v0.1 manifest is frozen. Do not replace a failed case, expose a fixing pull request or gold test to generation, select candidates using hidden-fix output, or silently rewrite result rows. Corrections that can affect a score require a new benchmark version or documented erratum under the rules in [evaluation.md](docs/evaluation.md).

## Pull requests

A useful pull request:

- explains the user-visible or security outcome;
- stays within one coherent concern;
- includes tests proportional to the risk;
- documents new CLI, report, protocol, policy, or failure behavior;
- avoids drive-by formatting or unrelated generated files; and
- states which commands above were run and any deliberate skip.

Do not include secrets, private issue content, proprietary repository snapshots, or model transcripts containing sensitive data.

## Reporting security problems

Do not open a public issue for a vulnerability. Follow the private reporting instructions in [SECURITY.md](SECURITY.md).
