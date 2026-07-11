# Roadmap

Date: 2026-07-10

Status: alpha and validation-ready, with **0/20 scored runs**. The 20-case selection, attested
dataset parser, exact upstream provenance, causal wheel executor, semantic issuer, scored runner,
pre-inference pricing/authorization barrier, executed controls, reviewer consensus, bounded
publication, and exact-SHA dependency-aware replay are implemented. Provider execution remains
default-deny at a $0 cap until exact authorization and all 20 private case packages pass. No model
spend or outreach occurred.

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

## Next: execute validation without moving the goalposts

The 20-case v0.1 cohort is frozen and
[`results.jsonl`](../benchmarks/v0.1/results.jsonl) is empty. Its historical snapshot cutoff is not
currently supportable from trusted evidence, so v0.1 remains blocked rather than being silently
reinterpreted. Exact-object source preparation now accepts and freshly reverifies 20/20 repositories;
that transport milestone does not satisfy the historical or evaluator gates. V0.2 therefore uses a
chronology-honest dataset-snapshot selection rather than relabeling v0.1. The next evidence slice is:

1. build and independently verify all 20 private source/dependency/hidden-fix case packages;
2. freeze the exact 20 rendered requests, tool revision, pricing snapshot, provider/model/adapter,
   per-case and campaign caps, and human approval bytes before provider-capable work;
3. submit exactly one candidate per frozen case and retain every attempt, failure, and cost event;
4. execute the declared causal controls and blinded two-reviewer/tie-break protocol;
5. publish the complete 20-case denominator, attributable cost, wall time, and replay bundles; and
6. record false reproductions, setup failures, flakiness, and infrastructure errors without hiding
   them from the denominator.

The provider-free dataset transaction and v0.2 exact-object source commands are implemented. A
fresh authentic local run materialized and independently rederived all 20 safe dataset projections
with zero provider calls. That closes input preparation only: complete source/dependency/hidden-fix
packages, genuine reviewer assignments, preregistration, and request/pricing authorization are still
required before a scored run.

Complete historical body revision capture remains an optional future upgrade to a stronger
chronology claim. It is not required for the current explicitly `chronology_unproven` cohort.

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
