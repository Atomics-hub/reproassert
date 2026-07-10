# Project status

Last updated: 2026-07-10

## Current verdict

**GO for the bounded local Python/pytest product slice. Exact source preparation now covers and
freshly reverifies all 20 frozen repositories. The historical generation campaign remains BLOCKED
pending a frozen v0.2 snapshot cohort with trusted captures, causally proven dependency/evaluator
packages, and production generator/evaluator isolation. Hosted-product and demand claims remain
deferred.**

## Verified now

- Installable Python 3.10+ package and `reproassert` CLI.
- Strict canonical GitHub issue intake, exact 40-hex commit resolution, bounded archive download,
  traversal/collision/link/bomb-resistant extraction, and a second no-follow source-tree attestation
  that reconstructs Git blob/tree object IDs before generation.
- One controller-chosen test path and function, strict JSON generator protocol, and AST policy
  rejection for obvious false-reproduction and execution patterns.
- Explicit opt-in OpenAI Responses adapter at a fixed endpoint, plus the provider-neutral command
  protocol and manual-candidate path. API-key presence alone never initiates a paid request.
- Hardened Docker verification with no host bind mount, no inherited environment, network off,
  read-only root/workspace, non-root user, capability drop, no-new-privileges, and CPU, memory,
  PID, file, tmpfs, timeout, log, and output limits.
- Candidate collection plus three clean targeted runs, exact failure classification, normalized
  fingerprinting, patch artifact, bounded JSON report, replay that regenerates commands and
  revalidates archive/tree identities, and successful-generation token/latency metadata.
- Public self-owned [issue #1](https://github.com/Atomics-hub/reproassert/issues/1) at exact commit
  `7b03e8f7f4b7312f1785e7853892efa123e48699` reaches `repeatable_base_failure` in 3/3 clean
  containers; a fresh report replay matches the fingerprint in another 3/3 runs. The local fixed
  source passes. This is infrastructure proof, not benchmark accuracy.
- Frozen public benchmark manifest: 20 historical cases across 10 repositories; five-case smoke
  subset; strict schemas and validator.
- Deny-by-default campaign freeze, separate hash-chained smoke/scored event ledgers, all-attempt
  accounting, provider-call spend reservation, and explicit unknown-cost failure states. Both
  ledgers and the result file remain empty.
- Exact-source preparation baseline: 16/20 archives passed independent fresh-metadata
  re-verification. Four failed closed: one Git submodule/gitlink, two tracked symlinks, and one
  codeload `export-subst` byte change. This used no model, authorized no spend, and changed no
  campaign/result/ledger bytes. See
  [`benchmarks/v0.1/source-preparation-baseline.json`](benchmarks/v0.1/source-preparation-baseline.json).
- Exact-object source preparation follow-up: 20/20 receipts accepted and independently reverified.
  Codeload is bounded bulk transport, not authority; the controller reconstructed complete Git
  trees, repaired four mismatched archive paths using three raw exact-OID fallback fetches, preserved
  16 root-confined tracked symlinks, and represented one gitlink as an empty uninitialized directory.
  Median local prepare/reverify time was 3.533/1.952 seconds. Private archives/receipts are not
  committed, no object-source index exists, no model ran, and campaign readiness stayed false. See
  [`benchmarks/v0.1/object-source-preparation-baseline.json`](benchmarks/v0.1/object-source-preparation-baseline.json).
- A standalone real-Docker generator/evaluator mount canary passed its positive and negative
  sentinel controls and cleanup. It is synthetic infrastructure evidence, not proof that the
  production benchmark generator is isolated.
- Historical snapshot validation is fail-closed. The v0.1 `pre_fix_source_snapshot` label remains
  unsupported. The v0.2 draft now has an offline-only producer that requires complete issue edit
  history, selects the last revision before fixing-PR publication, reruns exact redaction, and
  independently rederives the durable receipt. A live self-owned issue/PR fixture rederived the
  expected pre-publication revision; its bounded proof record is
  [`evidence/snapshot-producer-self-fixture.json`](evidence/snapshot-producer-self-fixture.json).
  There is still no authenticated collector or frozen v0.2 cohort; capture authenticity, fixing-PR
  selection, and human privacy review remain trusted inputs.
- Hash-locked wheel preparation primitives now cover strict plans, fixed source-free download and
  offline-install argv, bounded hostile-wheel inspection, a 512 MiB aggregate declared expansion
  cap, deterministic receipt fields, and an optional read-only dependency mount. Red-team review
  found no P0 but confirmed that fresh-volume ownership, inspected phase execution, image IDs, and
  wheelhouse-to-installed-tree causality are not yet implemented; dependency readiness remains 0/20.
- Prior regular-source milestone is public on protected `main` at commit
  `be5bdc2bd49f3ffa9b88fa5b30a7d6536f1b68d8`. The exact-object/snapshot/dependency implementation is
  bound to commit `24571bb72abd4c618a5a1e0fd8a881b403303519`: locally, 572 tests pass at 84.13%
  branch coverage on Python 3.10, the complete non-Docker suite passes on Python 3.11-3.14, clean
  wheel/sdist installs pass, two real Docker integration tests and the isolation canary pass, and
  the site rebuild/audit is green. No GitHub Actions run was used to reach this state.
- Public proof site and canonical report schema are live over HTTPS at
  <https://atomics-hub.github.io/reproassert/>. The deployed desktop/mobile surface has no detected
  horizontal overflow, overlap, console errors, or warnings.
- GitHub rulesets require pull requests, all nine CI contexts, linear history, and immutable `v*`
  tags. Vulnerability alerts, secret scanning/push protection, and immutable future releases are
  enabled. Automated security-fix PR creation is intentionally disabled after an initial noisy
  burst; version updates are grouped monthly and limited to one PR per ecosystem. Actions artifacts
  and logs retain for seven days; caches retain for seven days under the included 10 GB hard cap;
  redundant post-merge full CI is disabled; and every external contributor's fork workflow requires
  maintainer approval before execution. Repository policy requires every referenced Action to use a
  full-length commit SHA. Extended non-provider and validity-check secret scanning remained disabled
  after a repository API enablement request; no claim is made that those optional extensions are
  active.
- The site dependency graph passed both full `npm audit` and `npm audit --omit=dev` with zero known
  vulnerabilities at its recorded release check. This is point-in-time evidence, not a permanent
  vulnerability claim.

## Evidence still missing

- Historical benchmark results: **0/20 run**.
- Semantically valid benchmark reproductions: **0/20 measured**.
- Regular-file v1 source receipts: **16/20 accepted and independently reverified; four unsupported
  under that deliberately narrower policy**.
- Provenance-verified historical issue snapshots: **0/20 campaign-ready**.
- Prepared dependency images and hidden-fix evaluator packages: **0/20 campaign-ready**.
- Exact-object source receipts: **20/20 accepted and independently reverified locally**; private
  receipts are not a public index and have not changed the frozen campaign prerequisite.
- Independently validated or maintainer-accepted tests: **0**.
- Maintainers willing to use it again: **0**.
- Complete model cost across successful and failed generation attempts, warm runtime, and hosted
  runner COGS: **not measured**. A verified-candidate report does not capture aborted attempts.
- Paid pilots, qualified trials, and MRR: **0**.

## Next exact build slice

1. Publish the exact-object/snapshot/dependency preparation slice through one batched pull request
   and one planned existing CI cycle; do not create a release or reuse the immutable `v0.1.0` tag.
2. Freeze a corrected v0.2 cohort only after its evaluator-side fixing-PR mappings, raw GraphQL
   captures, privacy reviews, and generator-safe projections are complete and independently audited.
3. Implement the dependency executor: fresh labeled/empty volumes, constrained ownership, inspected
   image IDs and phase outcomes, wheelhouse-before-install and tree-after-install attestations,
   bounded disk/egress policy, causal receipt, and cleanup.
4. Wire exact-object source plus prepared dependencies into the scored generator/evaluator split and
   rerun the real isolation canary against that production path.
5. Authorize any model smoke only after every prerequisite is true and a separate explicit spend cap
   is recorded. Prepare maintainer-validation packets, but contact nobody without exact approval.

The active project goal is intentionally not marked complete while these validation gates remain.
