# Benchmark v0.2 draft

This directory is a design marker, not a frozen benchmark and not a scored campaign. It contains no
cohort manifest, model outputs, or results.

The v0.2 preparation contract replaces v0.1's unsubstantiated `pre_fix_source_snapshot` label with
the independently observable `pre_solution_pr_publication` cutoff. Snapshot receipts separately
record whether earlier private fix chronology is proven or unproven. That caveat never enters the
three-field generator projection and must never be turned into a “before anyone attempted a fix”
claim.

No v0.2 cohort is frozen yet. Case IDs and receipts used by the draft validator are fixtures until a
new manifest is preregistered. Benchmark v0.1 remains immutable, blocked, and at 0/20.

The current validator checks the strict receipt shape, byte commitments, chronology, privacy status,
and safe three-field projection. It does **not** yet parse raw edit history and independently derive
the selected revision or exact fixing-link redaction. Its default API therefore rejects projection
with `benchmark_snapshot_producer_unverified`; an explicit fixture-only override exists for producer
development. This draft cannot satisfy a campaign prerequisite.
