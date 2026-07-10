# 0004 — Historical snapshots require provenance, not a live-issue fallback

Status: accepted on 2026-07-10

## Context

Benchmark v0.1 froze the label `pre_fix_source_snapshot` before a durable snapshot receipt existed.
That label is stronger than the public source data currently proves. The upstream SWE-bench
collector reads the issue title and body returned by GitHub when the dataset is built; its
first-commit time filter applies to comment-derived hints, not to the issue statement itself.
TDD-Bench-Verified then filters SWE-bench Verified rows and removes test-transition columns; it does
not create an independent historical issue snapshot.

GitHub's current issue response is not proof of what the title and body contained before a solution
was authored or published. Retained edit events can support some cases, but missing edit events do
not prove that no prior version existed. Commit author timestamps are also useful provenance signals,
not tamper-proof evidence of when a human began work.

## Decision

- Keep benchmark v0.1 frozen and blocked at 0/20. Do not reinterpret or silently repair its declared
  cutoff after seeing the problem.
- Never use the live current issue response as a benchmark historical-snapshot fallback.
- A trusted preparation receipt must bind the selected UTF-8 title/body bytes to the case identity,
  base SHA, capture method, raw evidence digest, history-completeness statement, cutoff policy and
  timestamp, revision-selection provenance, redaction policy, privacy review, and preparation-tool
  revision.
- Generator-visible material contains only the sanitized title, body, and their snapshot digest.
  Raw history, cutoff-oracle material, fixing-PR identity, and evaluator records stay outside the
  generator trust domain.
- Evidence that cannot substantiate the declared cutoff fails closed as
  `historical_version_unproven`; it cannot be relabeled as a verified pre-fix snapshot.
- The next score-bearing benchmark version will use the independently observable
  `pre_solution_pr_publication` cutoff. It will separately record temporal provenance such as
  `issue_predates_solution_authorship` or `pre_fix_chronology_unproven`; PR-publication provenance
  must not be presented as proof that no private fix work had begun.
- Any v0.1 case correction that can affect scoring requires a new benchmark version, not a changed
  row in the frozen manifest.

## Consequences

Source-archive preparation, dependency work, and isolation canaries may continue without model
calls, but the v0.1 historical-snapshot prerequisite remains false. No smoke or scored model run may
start against these cases. Public claims stay limited to a hidden-fix historical evaluation design,
not “before anyone attempted a fix.”

The v0.2-draft offline producer now implements independent derivation for its supported frozen
GraphQL capture shape. That closes the code-path gap described here, but not the evidence gap: there
is no authenticated collector or frozen v0.2 cohort, and evaluator selection of the fixing PR,
capture authenticity, and the human privacy review remain trusted inputs.

Primary implementation evidence:

- [SWE-bench issue and hint extraction](https://github.com/SWE-bench/SWE-bench/blob/main/swebench/collect/utils.py)
- [TDD-Bench-Verified dataset preparation](https://github.com/IBM/TDD-Bench-Verified/blob/main/dataset_preparation.py)
