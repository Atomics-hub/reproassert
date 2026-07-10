# Benchmark release checklist

This checklist separates readiness, paid execution, blinded review, and publication. A checked
readiness box is not a benchmark result.

## 1. Freeze inputs before inference

- [ ] Exact 20-case preregistration validates and its public tree passes the private-artifact leak
  scanner.
- [ ] Every case binds the pinned buggy commit, generator projection, source-context digest,
  evaluator commitment, dependency receipt, and private hidden-fix package.
- [ ] Historical issue text is labeled by its real provenance. Dataset snapshots say
  `chronology_unproven` and `historical_public_contamination_exposed`; stronger chronology is used
  only with independently verified revision evidence.
- [ ] Direct fixing-PR references and deterministic gold-line overlap signals are excluded or
  quarantined before cohort freeze, with the rule and exclusions recorded.
- [ ] Generator-visible files contain no production patch, developer test, hidden verdict, oracle
  rubric, evaluator path, credential, or later-history artifact.
- [ ] The official semantic issuer rederives every source, dataset, patch-causality, dependency,
  isolation, and reviewer-role binding in the trusted controller.
- [ ] Campaign freeze fixes one provider/model, request builder, pricing snapshot, one-candidate
  policy, time/output limits, cost reservation, and hard case/campaign caps.

## 2. Obtain narrow approvals

- [ ] Tom has approved the exact spend sentence in
  [`spend-authorization-template.md`](spend-authorization-template.md), or the generator is a
  declared zero-cost offline adapter.
- [ ] Any third-party authenticated GitHub collection has separate least-privilege approval.
- [ ] No maintainer contact or public posting is bundled into either approval.

## 3. Generate without oracle access

- [ ] Each of 20 cases records exactly one durable disposition: one submitted candidate or one
  explicit no-candidate outcome.
- [ ] Provider calls, failures, timeouts, usage, reservations, and all attributable costs reconcile;
  unknown cost halts the campaign.
- [ ] Candidate bytes are written, fsynced, revalidated, and ledger-committed before a successful
  provider call is marked complete.
- [ ] All 20 disposition events and their campaign barrier are durably sealed before the first
  evaluator capability is acquired.
- [ ] Crash recovery reuses only the exact committed candidate and makes zero provider calls.

## 4. Evaluate and review

- [ ] Base/fixed runs use the frozen interleaved schedule and fresh sandbox environments.
- [ ] Setup, collection, wrong-failure, timeout, flake, fixed-failure, and infrastructure outcomes
  remain distinct.
- [ ] Reviewers see only the frozen issue text and candidate until all semantic verdicts are sealed;
  reviewer role is described no more strongly than its evidence supports.
- [ ] Every no-candidate case remains in the 20-case denominator.

## 5. Finalize and publish

- [ ] Offline finalization independently verifies the ledger, all 20 results, candidate barrier,
  costs, review timing, and public redaction.
- [ ] The public aggregate includes each candidate's bounded test content and one-command
  reproduction, or an explicit no-candidate disposition.
- [ ] Exact model version/date, historical-public contamination, total spend, failure taxonomy,
  runtime, semantic precision, and confidence interval are disclosed.
- [ ] Publication says `0/20` or `not measured` for every incomplete metric; no partial denominator
  is presented as the campaign result.
- [ ] One clean wheel install, schema export, source-distribution test, Docker run, and public
  artifact re-verification pass from the exact release commit.

