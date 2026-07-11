# ReproAssert

> The test before the fix.

ReproAssert turns a public GitHub issue into one candidate pytest regression test, then proves that
the test collects and fails consistently on the exact buggy commit inside a locked-down Docker
sandbox.

```text
GitHub issue + exact commit
           |
           v
candidate.patch + one-command replay + reproassert-report.json
```

It never edits production code. It never silently falls back to running repository code on your
host. Its strongest public CLI claim is deliberately narrow: **this test produced the same
issue-marked failure on the pinned base revision across repeated sandboxed runs.**

## Quick start

ReproAssert currently installs from source. You need Python 3.10+, [uv](https://docs.astral.sh/uv/),
and Docker Engine or Docker Desktop.

```console
git clone https://github.com/Atomics-hub/reproassert.git
cd reproassert
uv tool install .

reproassert sandbox build
reproassert doctor
```

Then run one issue against its buggy commit:

```console
reproassert issue https://github.com/OWNER/REPOSITORY/issues/123 \
  --commit <buggy-commit-sha> \
  --generator-command ./your-trusted-adapter
```

A verified run ends with concrete, replayable evidence:

```text
claim    repeatable_base_failure
outcome  repeatable_base_failure
patch    .../candidate.patch
report   .../reproassert-report.json
replay   reproassert replay .../reproassert-report.json
```

That result means the candidate collected and produced a stable, expected failure on the exact base
SHA. It does **not** mean the test passes on a fix, captures the issue's true semantics, or has been
accepted by a maintainer.

### Without uv

```console
git clone https://github.com/Atomics-hub/reproassert.git
cd reproassert
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .

reproassert sandbox build
reproassert doctor
```

The controller supports macOS and Linux. WSL is treated as Linux but is not yet independently
verified. Native Windows execution and Windows containers are unsupported. There is no native
execution fallback.

## Choose how the test is created

Every run requires exactly one candidate source.

### A trusted generator adapter

```console
reproassert issue https://github.com/OWNER/REPOSITORY/issues/123 \
  --commit <buggy-commit-sha> \
  --generator-command ./your-trusted-adapter \
  --pass-env PROVIDER_API_KEY
```

The adapter is a program you trust. ReproAssert sends it a bounded JSON request on stdin and expects
one JSON object on stdout containing `test_content`, `expected_symptom`, and `rationale`. It receives
untrusted issue and repository text, so it must keep those inputs in the data plane—not interpret
them as commands. Only environment variables named with `--pass-env` are forwarded.

See the working offline [deterministic adapter](examples/deterministic_generator.py) and the
[architecture](docs/architecture.md) for the protocol and trust boundary.

<details>
<summary>Generator protocol response</summary>

```json
{
  "test_content": "def test_issue_123_reproduction():\n    assert observed == expected, 'duplicate separators remain'\n",
  "expected_symptom": "duplicate separators remain",
  "rationale": "Exercises the user-visible normalization invariant."
}
```

The adapter must emit exactly those three string fields. The expected symptom must appear literally
in the test, normally as its assertion message. Output is capped at 64 KiB and execution at 300
seconds. The command runs directly without shell expansion.

</details>

### A human-written test

For issue `123`, create one synchronous test named `test_issue_123_reproduction`:

```python
from your_package import normalize


def test_issue_123_reproduction() -> None:
    observed = normalize("Alpha  Beta")
    assert observed == "alpha-beta", "duplicate separators remain"
```

Then verify it through the same policy and Docker boundary:

```console
reproassert issue https://github.com/OWNER/REPOSITORY/issues/123 \
  --commit <buggy-commit-sha> \
  --candidate-file ./candidate.py \
  --expected-symptom "duplicate separators remain" \
  --rationale "Exercises adjacent-space normalization through the public function."
```

### The built-in OpenAI adapter (explicit opt-in)

```console
export OPENAI_API_KEY="..."
reproassert issue https://github.com/OWNER/REPOSITORY/issues/123 \
  --commit <buggy-commit-sha> \
  --provider openai
```

The provider is never selected merely because an API key exists. The default model is
`gpt-5.4-mini`; use `--model MODEL` to choose another. This sends bounded public issue and selected
source context to `https://api.openai.com/v1/responses` and may incur charges on your account.
ReproAssert requests `store: false`, makes no automatic retries, and caps request, response, and
output sizes. Review your provider's data policy before use; the source-context filter is not a
data-loss-prevention system.

## What ReproAssert verifies

The first product profile is intentionally Python + pytest:

| Stage | Required evidence |
| --- | --- |
| Source | Canonical public issue, exact 40-character commit SHA, and files that reconstruct the commit's Git root tree |
| Candidate | One new synchronous pytest test, no production edits, strict static policy, at most 32 KiB |
| Collection | The candidate collects successfully inside Docker |
| Execution | It fails 2-10 times (default 3) with the expected symptom and a stable failure fingerprint |
| Boundary | No network, read-only root and workspace, non-root user, dropped capabilities, bounded CPU, memory, PIDs, time, and output |
| Result | A test-only patch, replay command, and machine-readable evidence report |

Syntax errors, collection/import/setup failures, missing dependencies, generic crashes, timeouts,
unrelated failures, and inconsistent one-off failures are rejected rather than counted as
reproductions. Ordinary `issue` runs do not install project dependencies; the current wedge is best
suited to repositories whose test environment is already self-contained under the strict profile.

The claim ladder stays explicit:

```text
rejected -> collected -> repeatable_base_failure  [public CLI ceiling]
                              |
                              +-> differential_reproduction  [capability-gated evaluation]
                              +-> maintainer_validated        [external evidence only]
```

## Inspect and replay the evidence

Run artifacts live under `$XDG_STATE_HOME/reproassert/runs` or
`~/.local/state/reproassert/runs`. Choose another controller-owned directory with `--run-base`.

- `candidate.patch` adds only `tests/reproassert/test_issue_NUMBER.py`.
- `reproassert-report.json` records issue and source provenance, the candidate and its digest,
  Docker policy and immutable image ID, collection and rerun outcomes, bounded logs, failure
  fingerprint, artifact hashes, and explicit limitations.

Replay a report with controller-owned commands:

```console
reproassert replay ~/.local/state/reproassert/runs/issue-.../reproassert-report.json
```

Replay reacquires and verifies the exact source, regenerates safe pytest arguments, and creates a
new report. It does not execute command-looking fields from the original report. A successful replay
is fresh bounded evidence—not semantic proof.

Print the exact report schema bundled with the installed controller without a network request:

```console
reproassert schema
```

The published schema is also available at
[`reproassert-report.schema.json`](https://atomics-hub.github.io/reproassert/reproassert-report.schema.json).

## Security model

Repository code, issue text, source files, dependencies, generated tests, pytest results, and
imported reports are untrusted. The verifier receives no host secrets, SSH agent, browser state,
cloud credentials, proxy variables, Docker socket, or unrelated host directories. Archive paths and
types are checked, accepted source files must reconstruct the pinned Git tree, and repository code
runs only inside Docker with the recorded restrictions.

Residual risk remains. Docker shares the Linux host kernel or Docker Desktop VM; hostile pytest
code may try to forge in-process result detail; and a user-selected generator adapter is a trusted
host process. Treat `repeatable_base_failure` as bounded evidence, not proof.

Before running an unfamiliar repository, read the [security model](docs/security-model.md),
[threat model](docs/threat-model.md), and [sandbox profiles](docs/sandbox-profiles.md). Report
vulnerabilities through GitHub's private process described in [SECURITY.md](SECURITY.md), not a
public issue.

## Benchmark status

Measured results remain intentionally separate from product capability.

- v0.1 is immutable at **0/20** because of its [provenance erratum](benchmarks/v0.1/ERRATA.md).
- v0.2 freezes 20 leak-audited cases from pinned upstream data and independently attests the parser
  boundary and exact Git object graph.
- The v0.2 cohort remains **0/20 scored runs, 0/20 L1, 0/20 L2, and zero maintainer validations**.
- No scored model spend or maintainer outreach has occurred.
- The zero-spend preparation lane has authentically extracted 20/20 hidden evaluator records and
  built 20/20 provider-disabled pre-review packets. Dependency-ready and campaign-ready counts are
  still 0/20; these are not scored case packages.

The v0.2 preparation and evaluation machinery is default-deny: source, dependency, hidden-fix,
request, pricing, authorization, causal-control, and reviewer commitments must be bound before a
provider-capable run. Its issue snapshots remain labeled `chronology_unproven` and
`historical_public_contamination_exposed`; no historical-cleanliness claim is implied.

The final exact-image authorization is also fail-closed on spend. `reproassert benchmark
prepare-v02-execution-freeze` recomputes all 20 worst-case request reservations and binds the merged
controller SHA before emitting its final hash. A separate `authorize-v02-execution` command accepts
only a later $5 total / $0.25 per-case zero-overage approval naming that exact hash. Neither command
reads a provider key or makes a provider call. See
[ADR 0014](docs/decisions/0014-exact-image-campaign-freeze-and-request-cap.md).

See the [v0.2 protocol](benchmarks/v0.2-draft/README.md), [evaluation model](docs/evaluation.md), and
[market-validation gates](docs/market-validation.md). Passing the internal 6/20 continuation gate
would justify more validation; it would not establish a general 30% success rate, superiority, or
maintainer demand.

## Development

```console
git clone https://github.com/Atomics-hub/reproassert.git
cd reproassert
uv sync
uv run pytest
uv run ruff check .
uv run mypy src
```

Start with [CONTRIBUTING.md](CONTRIBUTING.md). The deeper product contract lives in:

- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Evaluation protocol](docs/evaluation.md)
- [Roadmap](docs/roadmap.md)
- [Business model](docs/business-model.md)
- [Launch plan](docs/launch-plan.md)

ReproAssert is alpha software available under the [MIT License](LICENSE).
