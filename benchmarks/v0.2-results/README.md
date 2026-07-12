# ReproAssert benchmark v0.2.1 results

This is the complete public result projection from the first frozen v0.2.1 campaign, executed on
2026-07-12. The result is **0 accepted out of 20 evaluated**.

| Measure | Observed |
| --- | ---: |
| Frozen cases / provider calls | 20 / 20 |
| Accepted L1 deterministic reproductions | 0 / 20 |
| Candidate-contract rejections | 17 / 20 |
| Exact-image sandbox evaluations | 3 / 20 |
| Sandbox outcomes | 3 `wrong_or_flaky_failure` |
| Total provider spend | $0.688111 |
| Minimum / maximum case spend | $0.022471 / $0.051351 |
| L2 / human-reviewed / maintainer-validated | 0 / 0 / 0 |

Cases 003, 007, and 011 each produced three base exit-code failures and three fixed-tree passes, but
none produced the required stable attributable JUnit failure fingerprint. They are rejected, not
near-miss successes. The other 17 outputs failed the preregistered candidate contract before
sandbox execution. The frozen rules were not relaxed and no case was regenerated after outcomes
were visible.

The campaign missed its preregistered continuation target of at least 6/20. Cost per accepted
reproduction is therefore undefined. This result does not support an accuracy, semantic validity,
maintainer demand, hosted readiness, or business claim.

## Files

- [`campaign-summary.json`](campaign-summary.json) is the small human- and machine-readable result
  projection with spend, counts, commitments, and claim limits.
- [`aggregate.json`](aggregate.json) is the canonical self-hashed 20-case aggregate.
- [`cases/`](cases/) contains 20 redacted public case receipts and the three exact-image evaluator
  receipts. They contain digests and bounded phase facts, not provider output, raw logs, hidden
  patches, credentials, or private paths.

Verify the aggregate and its case bindings from a source checkout:

```console
uv run python -c 'from pathlib import Path; from reproassert.benchmark_v021_automated_evaluation import inspect_v021_automated_evaluation_set as inspect; print(inspect(Path("benchmarks/v0.2-results/aggregate.json"), receipt_directory=Path("benchmarks/v0.2-results/cases")))'
```

Structural inspection checks canonical encoding, self-hashes, the complete denominator, case and
evaluator receipt bindings, claim ceilings, candidate commitments, and evaluator tool attribution.
It deliberately does not mint the process-local live execution authority used during the run.

