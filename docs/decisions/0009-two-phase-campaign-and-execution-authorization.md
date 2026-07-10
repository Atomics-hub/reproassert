# 0009 — Freeze all generation before evaluator access

Status: accepted and locally implemented; no scored campaign authorized, on 2026-07-10

## Context

Committing one candidate before evaluating that same case prevents within-case oracle feedback, but
it does not prevent verdicts from earlier cases influencing later generation. A trustworthy 20-case
score also needs proof that the provider, model, exact rendered inputs, prices, call budget, time
budget, and spend caps were authorized before the first request. An API key, a preparation-only
campaign record, or a hash first written by attempt one is not that proof.

Crashes create a second integrity problem. A provider may have charged for a response even when the
process dies before its normal ledger events. Retrying that call silently would change both cost and
best-of-N semantics.

## Decision

The v0.2 scored path is split into irreversible phases:

1. A public preparation freeze binds the exact preregistration, ordered 20-case cohort, tool commit,
   and the requirement for an all-case generation barrier. It authorizes no provider.
2. A separate private execution-authorization record is created only from exact approval. It binds
   the preparation freeze, preregistration, cohort, tool commit, all 20 rendered-input hashes,
   provider, exact requested model, adapter configuration, full canonical pricing snapshot, one-call
   policy, time/output limits, per-case reservation, hard case/campaign caps, authorization time,
   exact approval-text commitment, and immutable approval reference.
3. `generate_v02_scored_case` has no evaluator argument. Each case durably records exactly one
   `generation_disposition_frozen`: one validated candidate or one explicit no-candidate outcome.
4. Only after all 20 dispositions exist may the controller write one
   `campaign_generation_barrier_frozen` event. Its digest commits the ordered disposition set,
   execution authorization, request set, configuration, pricing, and safe run provenance.
5. `evaluate_v02_frozen_case` is the only evaluator entry point and rejects a missing, incomplete,
   changed, or post-hoc barrier. No-candidate cases remain in the denominator without acquiring an
   evaluator capability.
6. Crash recovery can consume only the exact fsynced generation transaction. It permits zero new
   provider calls and zero evaluator access, records unknown cost fail-closed, and cannot substitute
   a candidate or use oracle feedback.

Every provider call, including failure, timeout, no output, or crash, must reconcile to one exact
cost record. Known campaign spend plus active reservations plus the next reservation must fit below
the hard campaign cap before another call begins.

## Consequences

The controller can prove its own event ordering and reject post-hoc configuration drift. It can also
resume a paid response without buying a second trajectory. Generation is slower because evaluation
waits for all 20 cases, and the hard cap must accommodate all active reservations at the barrier.

The record is not a cryptographic signature from the user or provider. Its approval reference and
exact text commitment must remain independently recoverable, and the private evidence bundle must
be protected from rewriting. A future hosted service should sign the authorization and ledger with
an account-bound key or supply a verifiable attestation.

This decision establishes campaign integrity machinery only. It does not authorize spend, prove the
historical issue-text chronology, create an authentic case package, establish L2 semantic validity,
contact a maintainer, or change the current 0/20 result.

