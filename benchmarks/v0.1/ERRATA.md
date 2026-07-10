# Benchmark v0.1 provenance blocker

The frozen manifest declares an issue-snapshot cutoff named `pre_fix_source_snapshot`. ReproAssert
does not currently have evidence receipts that substantiate that claim for all 20 cases.

The upstream dataset construction reads issue title/body data from GitHub and applies its
pre-first-commit cutoff to comment-derived hints, not to the issue statement. A current live issue is
therefore not an acceptable historical fallback, and an absence of retained edit events is not proof
that the current body is the original body.

This file does not alter or reinterpret the frozen v0.1 protocol. The campaign remains
`blocked_pending_prerequisites`, with zero authorized spend and 0/20 results. No model-based smoke or
scored run may begin under v0.1 unless trusted evidence can support its declared cutoff. A
score-affecting correction requires benchmark v0.2.

The corrected preparation contract is recorded in
[`docs/decisions/0004-historical-snapshot-provenance.md`](../../docs/decisions/0004-historical-snapshot-provenance.md).
