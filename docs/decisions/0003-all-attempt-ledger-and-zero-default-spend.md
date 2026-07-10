# 0003 — All-attempt ledger and zero-default benchmark spend

Status: accepted on 2026-07-10

## Context

The first benchmark contract recorded a terminal case row, but a provider request that failed before
candidate verification could disappear from that row. The schema also could not prove event order,
distinguish unknown cost from zero, or prevent the same case from being rerun under another run ID.
That made success and cost vulnerable to survivorship bias. The scored evaluator prerequisites are
also incomplete, and no paid model budget has been explicitly authorized.

## Decision

- Keep `results.jsonl` as one terminal, derived projection per frozen case.
- Record every smoke and scored side effect in separate canonical JSONL event ledgers. Each event has
  a contiguous sequence, previous-event hash, and canonical self-hash. CI requires the previous
  public ledger bytes to remain an exact prefix.
- Fsync `attempt_started`, `phase_started`, and `model_call_started` before their side effects. A
  crash therefore leaves an open event whose time and cost are unknown; it never becomes `$0`.
- Freeze one canonical scored campaign before inference: exact tool commit, request builder, prompt
  template, context algorithm, provider/model identity, policy, pricing basis, feedback policy, and
  budgets. Record each case-specific rendered-input hash separately rather than treating it as
  cross-case configuration.
- Keep that experiment-defining campaign freeze immutable after the first scored event. The only
  permitted later edit is the monotonic `running` to `complete` status transition after all 20
  terminal rows and the deterministic summary are complete.
- Permit at most one model call and one submitted candidate per v0.1 case. Only independently proven
  infrastructure failures may retry, at most once in one linear chain, and they may not best-pick a
  new candidate. Cumulative phase time remains under the frozen per-case wall cap.
- Store money as integer micro-USD. Every component is measured, estimated, unknown, or verified
  zero. Unknown or estimated attributable spend makes the automated cost gate not evaluable.
- Enclose each provider call inside its durable generation-phase interval. A call that exceeds or
  escapes that interval is added as a runtime floor, invalidates the trace, and cannot make the
  wall-time gate pass.
- Commit canonical issue-snapshot, policy, base/fixed execution, causal-control, and semantic-review
  projections as hashed phase artifacts. Result reconciliation requires every candidate field,
  reviewer packet, rubric answer, outcome, timestamp, execution-environment hash, and attributable
  cost category to match the event trace.
- Keep public smoke and scored traces physically separate. Before scoring, smoke is deterministic
  offline harness work; a live model output on a frozen issue cannot be discarded as smoke.
- Keep the paid-provider caps at zero and campaign status blocked until Tom supplies an exact spend
  authorization or the campaign selects a declared zero-cost offline generator, and until issue
  snapshots, exact-SHA archives, evaluator artifacts, dependency images, isolation canaries, and
  reviewer roles are ready. Paid scoring additionally requires a frozen component pricing snapshot
  and trusted worst-case reservation calculator; an authorization reference alone cannot unlock it.

## Consequences

The five-case live-model smoke is intentionally not run yet. Passive public archive checks and
offline fixture tests remain safe. Aggregate success, runtime, and cost gates can turn green only
from complete reconciled evidence across all 20 cases; a narrative path to lower cost never changes
the automated gate. This adds event/reducer complexity, but it makes missing attempts and missing
money visible instead of optimistic.
