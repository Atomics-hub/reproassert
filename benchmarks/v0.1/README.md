# ReproAssert benchmark v0.1

This directory freezes ReproAssert's first public historical benchmark before any scored generation run. Its status is `preregistered_no_results`: the cohort and pass/fail rules are published, but no result is claimed yet.

The benchmark asks one narrow question: given only a public issue snapshot and the exact buggy repository commit, can ReproAssert produce one test-only patch that reliably fails for the reported symptom, passes after a hidden human fix, and survives blinded semantic review?

## Contents

- `manifest.json` freezes 20 issue/base-commit pairs across 10 Python repositories.
- `results.jsonl` is the append-only ledger for scored case records. It is intentionally empty at freeze time.
- [`../../schemas/benchmark-case.schema.json`](../../schemas/benchmark-case.schema.json) defines public case metadata.
- [`../../schemas/benchmark-run.schema.json`](../../schemas/benchmark-run.schema.json) defines an auditable scored run record.
- [`../../docs/evaluation.md`](../../docs/evaluation.md) defines the evaluator, leakage controls, outcomes, metrics, and claim limits.

Validate the freeze without installing ReproAssert or any third-party package:

```console
python3 scripts/validate_benchmark.py
```

The validator checks the exact cohort size, neutral unique case IDs, canonical issue URLs, full base SHAs, declared aggregate counts, five-case smoke subset, absence of evaluator-only oracle data, and any JSONL result rows.

## Cohort and smoke subset

All 20 cases are drawn from the 449-case TDD-Bench-Verified release. They are a deliberately judgmental easy-to-medium feasibility cohort, not a random or representative sample of GitHub issues. Historical issue and fix data are public, so model pretraining contamination cannot be ruled out.

The five smoke cases are only for exercising the harness before a scored run:

| Case | Repository | Issue |
| --- | --- | --- |
| `rk-v0.1-004` | matplotlib/matplotlib | [#24127](https://github.com/matplotlib/matplotlib/issues/24127) |
| `rk-v0.1-006` | scikit-learn/scikit-learn | [#13070](https://github.com/scikit-learn/scikit-learn/issues/13070) |
| `rk-v0.1-010` | pytest-dev/pytest | [#7981](https://github.com/pytest-dev/pytest/issues/7981) |
| `rk-v0.1-011` | pydata/xarray | [#4074](https://github.com/pydata/xarray/issues/4074) |
| `rk-v0.1-018` | pallets/flask | [#5010](https://github.com/pallets/flask/issues/5010) |

Smoke outcomes do not replace the complete 20-case score.

## Freeze and oracle boundary

The public manifest contains only neutral case IDs, repository names, issue URLs, buggy base SHAs, difficulty buckets, titles, and smoke flags. It deliberately excludes fixing pull requests, fixed commits, production patches, developer tests, oracle rubrics, and control patches. Those evaluator-only materials must never be mounted into the generation sandbox.

After dependency preparation, generation runs with network access disabled. The generator receives the frozen pre-fix issue title/body and base tree only. Issue comments and links back to the fixing pull request are excluded. One candidate is selected without consulting the hidden fix.

The cohort is immutable for v0.1. A failed case may not be replaced. A factual correction requires a documented erratum; any change that can affect a score requires a new benchmark version. Result rows are append-only and must retain failures and infrastructure errors.

## Claim ceiling

The primary metric is `semantic_valid_success_at_1`. A repeated fail-to-pass result is evidence, not proof of semantic correctness. It counts only after causal controls and blinded review establish that the generated trigger and oracle reproduce the issue rather than incidental patch behavior.

The internal continuation gate is at least 6 semantic-valid cases out of 20. Because this cohort is small, selected, and contamination-exposed, meeting that gate supports further product validation only; it does not establish a general 30% success rate. Maintainer acceptance and willingness-to-reuse are separate external gates and require separately authorized outreach.
