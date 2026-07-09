# ADR 0002: Separate mechanical failure from semantic reproduction

- Status: accepted
- Date: 2026-07-09

## Decision

ReproAssert uses four public claim levels:

1. `collected`: the candidate compiles and pytest resolves the intended node.
2. `repeatable_base_failure`: that node fails for the expected symptom with one stable fingerprint
   across the recorded buggy-base runs.
3. `differential_reproduction`: an evaluator-hidden production fix makes the same candidate pass
   while counterfactual checks do not expose an incidental transition.
4. `maintainer_validated`: a real maintainer independently validates or accepts the candidate.

The live unresolved-issue CLI cannot rise above `repeatable_base_failure`. The historical benchmark
counts success only after differential evaluation and blinded semantic review.

## Why

A failing test can be syntactically valid yet irrelevant, flaky, dependent on a fix-only symbol, or
made green by an incidental patch hunk. Published systems including BLAST and BRT Agent show that
fail-to-pass plausibility overstates developer-judged validity. The product is an evidence layer, so
the report must preserve that distinction rather than hide it behind a boolean `verified` field.

## Consequences

- Reports expose `claim_level` and a precise outcome taxonomy, not `safe: true` or `correct: true`.
- The benchmark generator never receives fix, gold-test, PR, or evaluator-oracle data.
- Marketing and README copy stay at "verified failing reproduction candidate" until stronger
  evidence exists.
