# Roadmap

Date: 2026-07-09

Status: alpha, strict Python/pytest base-failure slice implemented; benchmark preregistered with
0/20 scored runs. All-attempt accounting is fail-closed and the scored campaign is deliberately
blocked at a $0 paid-provider cap until exact spend authorization and evaluator prerequisites exist.
The provider observer and ledger writer are implemented, but the scored runner that owns the full
attempt-to-cost-to-result lifecycle is not; the campaign cannot transition to `frozen_ready` yet.

This roadmap is ordered by evidence, not feature count. A later phase does not begin because the earlier phase has more code; it begins when the earlier claim is reproducible and useful.

## Now: make `repeatable_base_failure` trustworthy

Implemented today:

- canonical public GitHub issue intake and exact SHA resolution;
- bounded archive download, safe extraction, and bounded source context;
- explicit built-in OpenAI Responses adapter, protocol-v1 trusted command adapter, and
  manual-candidate path;
- strict one-test AST policy and test-only patch generation;
- pinned Docker image build, `doctor`, no-network verification, resource limits, and no native fallback;
- collection plus 2-10 repeated base runs, deterministic failure classification, and fingerprinting;
- `candidate.patch`, schema-1.0 `reproassert-report.json`, and bounded replay; and
- a local Docker integration fixture covering repeated buggy failure and fixed-fixture `pass_on_base` classification.

Current limits are part of the product contract, not hidden backlog:

- public GitHub only;
- Python/pytest only;
- no repository dependency installation;
- one synchronous test in `tests/reproassert/`;
- one candidate per CLI run; and
- public claim ceiling `repeatable_base_failure`.

Before the first release is described as usable:

- keep lint, format, strict typing, unit, adversarial, Docker integration, benchmark validation, coverage, and package-build gates green;
- verify source and built-artifact installation in clean environments;
- keep CLI help, README examples, security docs, and report schema synchronized; and
- record known failures rather than widening the claim.

## Next: run benchmark v0.1 without moving the goalposts

The 20-case historical cohort is frozen and [`results.jsonl`](../benchmarks/v0.1/results.jsonl) is empty. The next evidence slice is to implement and operate the evaluator described in [evaluation.md](evaluation.md):

1. prepare per-repository dependencies through bounded, recorded, hashable images;
2. preserve the generator/hidden-fix boundary;
3. submit exactly one candidate per frozen case;
4. run interleaved repeated base and hidden-fixed verification;
5. apply declared causal controls and blinded semantic review;
6. append every terminal result, including failures and infrastructure errors; and
7. publish attributable cost and wall time without excluding failed attempts.

Continuation requires at least 6/20 semantic-valid cases, median warm runtime below 10 minutes, and attributable cost at or below roughly $1 per semantic-valid reproduction or a measured path there. Passing supports further validation only; it does not establish a population rate or state of the art.

## Then: maintainer usefulness

Maintainer outreach remains separately approval-gated. After exact approval:

- prepare on-demand artifacts for qualified Python/pytest maintainers;
- obtain at least one independently accepted or validated generated test;
- obtain three maintainers willing to use the workflow again;
- record requested edits and rejection reasons; and
- test whether teams will pay the proposed pilot price in [business-model.md](business-model.md).

Do not count stars, fixture passes, benchmark L0 results, compliments, or free trials as maintainer validation.

## Productize only after the gates

If internal and external gates pass, prioritize:

1. **Dependency preparation profiles.** Explicit reviewed network policy, reproducible image inputs, cache provenance, and per-repository failure reporting.
2. **Differential verification.** Repeated base/fixed execution and a claim that remains below semantic validity without causal review.
3. **Additional provider adapters.** Add only measured, auditable adapters that keep credentials explicit and issue/repository content untrusted.
4. **Opt-in GitHub workflow.** Manual dispatch, label, or requested Check; exact commit required; no automatic third-party issue spam.
5. **Report verification and export.** Stable schema evolution, redaction guidance, and independent artifact inspection.

Only after repeat demand should the project consider managed private-repository runners, hosted retention, team policy, concurrency, billing, or Marketplace distribution.

## Later, not promised

- additional Python test frameworks;
- JavaScript/TypeScript, Java, or other language adapters;
- self-hosted organization runners;
- observability or customer-report intake beyond GitHub Issues; and
- benchmark expansion beyond the selected historical cohort.

These are exploration directions, not commitments or current compatibility claims.

## Explicit non-goals

ReproAssert will not become a general coding-agent dashboard in the current bet. The core workflow does not:

- silently fix production code;
- treat issue instructions as commands;
- run hostile repositories on the host;
- automatically contact maintainers or open third-party pull requests;
- turn any failing test into a semantic-success claim; or
- hide the free local correctness path behind a hosted subscription.

See [market validation](market-validation.md), [launch plan](launch-plan.md), and [architecture](architecture.md) for the evidence gates, distribution order, and current boundary.
