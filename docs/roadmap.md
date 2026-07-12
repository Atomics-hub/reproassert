# Roadmap

Date: 2026-07-12

Status: alpha with one complete, failed validation campaign: **20/20 evaluated, 0/20 accepted**.
Exactly 20 frozen OpenAI calls cost $0.688111; 17 outputs failed the candidate contract and three
failed deterministic attribution because an evaluator JUnit transport bug discarded tmpfs output
after container exit. The current profile missed the 6/20 continuation gate.
No L2, human-review, maintainer-demand, or revenue claim is supported; no outreach occurred.

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
- `pristine tree + exactly one revalidated candidate`, candidate-applied/staged executed-tree
  attestation, schema-1.1 `reproassert-report.json`, and schema-1.0 backward replay;
- an inspected, quota-bounded JUnit result-volume anchor; and
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

## Next: learn from the failed campaign without moving the goalposts

The v0.1 cohort remains immutable under its provenance erratum. The v0.2.1 successor preserved the
full denominator, exact requests, hidden-fix isolation, spend ledger, and fail-closed evaluator. Its
0/20 result is now the baseline. The next evidence slice is:

1. preserve the exact first-run artifacts and never reclassify or replace a failed case;
2. analyze contract failures without hidden fixes to improve candidate-policy compliance;
3. repair and regression-test the JUnit transport without retroactively changing v0.2.1;
4. preregister any successor prompt/model/contract and a fresh capped budget before execution; and
5. keep benchmark results separate from organic GitHub usage and maintainer-demand evidence.

The first run stayed below its frozen $5 total / $0.25 per-case caps. It measured $0.688111 total,
$0.022471 minimum, and $0.051351 maximum. Since there were no accepted reproductions, cost per
success is undefined and the cost-efficiency gate did not pass.

Complete historical body revision capture remains an optional future upgrade to a stronger content
cleanliness claim. The current receipt proves creation order, not that the later dataset snapshot
contains only text visible before the fix attempt.

The preregistered continuation threshold was at least 6/20 accepted cases. The observed 0/20 does
not support scaling this profile. A successor experiment must earn a new decision on its own terms.

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

1. **Dependency preparation profiles.** Extend the implemented wheel-only causal executor only where explicit reviewed network policy, reproducible image inputs, cache provenance, and per-repository failure reporting remain enforceable.
2. **Differential verification.** Productize the implemented capability-gated repeated base/fixed primitive without upgrading it to semantic validity absent causal review.
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
