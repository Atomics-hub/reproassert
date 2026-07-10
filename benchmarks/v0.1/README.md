# ReproAssert benchmark v0.1

This directory freezes ReproAssert's first public historical benchmark before any scored generation run. Its status is `preregistered_no_results`: the cohort and pass/fail rules are published, but no result is claimed yet.

**Provenance blocker:** the frozen `pre_fix_source_snapshot` label is not yet supported by trusted
historical receipts for all 20 cases. The campaign stays blocked at zero authorized spend and 0/20;
see [`ERRATA.md`](ERRATA.md). A current live issue response is never accepted as a historical
fallback.

The benchmark asks one narrow question: given only a public issue snapshot and the exact buggy repository commit, can ReproAssert produce one test-only patch that reliably fails for the reported symptom, passes after a hidden human fix, and survives blinded semantic review?

## Contents

- `manifest.json` freezes 20 issue/base-commit pairs across 10 Python repositories.
- `campaign.json` is the deny-by-default scored-run freeze. It currently blocks inference and
  enforces a zero paid-provider budget until the missing evaluator prerequisites and an explicit
  spend authorization (or a declared offline generator) exist.
- `results.jsonl` is the append-only ledger for scored case records. It is intentionally empty at freeze time.
- `ledger/smoke-events.jsonl` and `ledger/scored-events.jsonl` are separate canonical,
  hash-chained all-attempt event ledgers. Both are intentionally empty.
- `summary.json` is the deterministic aggregate projection; gates remain not evaluable at 0/20.
- [`../../schemas/benchmark-case.schema.json`](../../schemas/benchmark-case.schema.json) defines public case metadata.
- [`../../schemas/benchmark-run.schema.json`](../../schemas/benchmark-run.schema.json) defines an auditable scored run record.
- [`../../schemas/benchmark-event.schema.json`](../../schemas/benchmark-event.schema.json) and
  [`../../schemas/benchmark-campaign.schema.json`](../../schemas/benchmark-campaign.schema.json)
  define the event and run-freeze contracts.
- [`../../docs/evaluation.md`](../../docs/evaluation.md) defines the evaluator, leakage controls, outcomes, metrics, and claim limits.

Validate the freeze without installing ReproAssert or any third-party package:

```console
python3 scripts/validate_benchmark.py
```

### Exact-source preparation (no model call)

The preparation-only CLI pins this manifest's exact checked-in SHA-256, fetches fresh Git commit-tree
metadata without authentication, downloads the codeload archive, and writes the archive plus a
deterministic receipt under a private `0700` output root:

```console
reproassert benchmark prepare-source rk-v0.1-018 \
  --manifest benchmarks/v0.1/manifest.json \
  --output-root <private-output-root> \
  --tool-git-sha <exact-controller-git-sha>

reproassert benchmark verify-source \
  <private-output-root>/rk-v0.1-018/benchmark-source-receipt.json \
  --manifest benchmarks/v0.1/manifest.json \
  --case-id rk-v0.1-018
```

After all 20 case receipts exist, `benchmark build-source-index` re-fetches every commit tree,
re-extracts and reattests every archive, and writes one deterministic index. It refuses missing,
duplicate, mixed-manifest, mixed-policy, mixed-producer, noncanonical, or tampered receipts:

```console
reproassert benchmark build-source-index \
  --manifest benchmarks/v0.1/manifest.json \
  --receipts-root <private-output-root> \
  --tool-git-sha <exact-index-builder-git-sha>
```

These commands never invoke a generator/model or edit the campaign/ledger. Source-only success does
not repair the historical-snapshot erratum and does not flip `exact_sha_archives_ready` or any other
campaign prerequisite. Archives stay in private user state and are intentionally not committed to
this repository.

Regenerate the deterministic projection to stdout (the validator also requires byte identity with
the checked-in `summary.json`):

```console
python3 scripts/summarize_benchmark.py
```

The validator checks the exact cohort, campaign and schema contracts, result cross-field evidence,
both event hash chains and lifecycles, spend/timeout caps, event-to-result reconciliation, the
deterministic summary, and absence of evaluator-only oracle data. Pull-request CI additionally
requires old ledger/result bytes to remain an exact prefix and the frozen manifest to remain
byte-identical. It does not make a network or model request.

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

### Public smoke lane and scored lane

The smoke lane is public, non-scored harness proof. Before the scored campaign it is limited to
deterministic offline fixtures, archive/setup checks, and control artifacts—no live candidate model
may touch a frozen case. A real model output on one of these five issues would be retained as that
case's sole attempt rather than discarded as harness smoke. Smoke may never expose fixed snapshots,
production patches, developer tests, semantic rubrics, or scored verdicts to the generator.

The scored lane starts only after the tool, prompt template, request builder, image, limits, attempt
budget, and evaluator are frozen. Each call separately records the hash of its case-specific rendered
input; that digest is expected to differ across issues and is never mistaken for template drift.
Each of the 20 cases then runs fresh without feedback from another case or adaptive tuning from its
result. The five smoke IDs remain members of the frozen cohort; deterministic harness activity does
not change the denominator.

## Freeze and oracle boundary

The public manifest contains only neutral case IDs, repository names, issue URLs, buggy base SHAs, difficulty buckets, titles, and smoke flags. It deliberately excludes fixing pull requests, fixed commits, production patches, developer tests, oracle rubrics, and control patches. Those evaluator-only materials must never be mounted into the generation sandbox.

The trusted preparation controller resolves the declared full base SHA and produces a content-addressed source archive from that exact commit. The generation workspace is extracted from that archive, not mounted from a clone: it contains no `.git` directory or file, remote configuration, refs, reflogs, object database, alternate worktree metadata, or commits after the base SHA. The archive digest and extracted-tree digest are recorded, and the fixed source archive remains evaluator-only.

After dependency preparation, generation runs with network access disabled. The generator may
receive only a provenance-verified historical issue title/body and exact-SHA base archive. Issue
comments are excluded; redaction is receipt-bound and evaluator-controlled. The fixing-PR identity
and raw history never enter the generator trust domain. One candidate is selected without consulting
the hidden fix.

The cohort is immutable for v0.1. A failed case may not be replaced. A factual correction requires a documented erratum; any change that can affect a score requires a new benchmark version. Every
attempt and infrastructure error remains in the append-only event ledger. `results.jsonl` receives
one derived counted projection per case only after its trace is terminal and its cost is known; it
cannot contain best-picked reruns under new run IDs.

## Campaign, attempt, and candidate accounting

A **campaign** is the single scored run for one frozen case under its predeclared total time,
model-call, and cost limits. An **attempt** is one started model trajectory inside that campaign. A
**candidate** is a decoded, policy-checkable patch produced by that attempt; exactly one candidate
may be submitted for scoring.

The immutable campaign trace retains every started attempt and any submitted candidate, including
no-output, rejected, timed-out, setup-failed, and otherwise unsuccessful work. Provider text and raw
error bodies are not published; an undecodable output is represented by its bounded classification,
safe response-ID hash when available, usage state, and full attributable cost. The public result row
summarizes the trace. Attempt accounting starts before a provider request or local model generation;
stopping before a usable patch does not remove its latency or spend.

Provider calls must fit inside their recorded generation phase; escaped duration is a conservative
runtime floor and a validation failure. Phase artifacts commit the canonical issue snapshot, policy,
verification, control, and reviewer evidence projected into each result row; execution phases also
commit the published environment hash. A matching terminal-row hash alone therefore cannot
substitute different inputs, candidate fields, reviewers, or execution evidence.

Budgets are fixed before the scored lane begins. No success-rate or cost claim may silently expand the number of attempts, select with hidden-fix feedback, discard failed campaigns, or report successful attempts alone. Alongside `semantic_valid_success_at_1`, reports distinguish first-attempt success from success within the frozen campaign budget and compute cost per semantic-valid success from total spend across every started attempt.

## Claim ceiling

The primary metric is `semantic_valid_success_at_1`. A repeated fail-to-pass result is evidence, not proof of semantic correctness. It counts only after causal controls and blinded review establish that the generated trigger and oracle reproduce the issue rather than incidental patch behavior. Reports separately count plausible fail-to-pass candidates that are semantic false reproductions and publish their rate among all plausible fail-to-pass candidates; a zero denominator is reported as undefined, not zero.

The internal continuation gate is at least 6 semantic-valid cases out of 20. Because this cohort is small, selected, and contamination-exposed, meeting that gate supports further product validation only; it does not establish a general 30% success rate. Maintainer acceptance and willingness-to-reuse are separate external gates and require separately authorized outreach.

The protocol is grounded in the hidden-oracle harness of [TDD-Bench Verified](https://arxiv.org/html/2412.02883), the transition definitions of [SWT-Bench](https://arxiv.org/html/2406.12952), and BLAST's finding that mechanical fail-to-pass can still be a [false reproduction](https://arxiv.org/html/2509.01616). The complete source notes and resulting safeguards are in [`docs/evaluation.md`](../../docs/evaluation.md#primary-methodological-anchors).
