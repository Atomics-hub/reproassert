# Project status

Last updated: 2026-07-10

## Current verdict

**GO for validation-ready local Python/pytest infrastructure. The 20-case v0.2 selection is frozen
from a container-attested, leak-audited upstream dataset; the scored runner, exact pricing and spend
authorization barrier, causal evaluator, two-reviewer/tie-break semantic gate, publication verifier,
and exact-SHA dependency-aware replay path are implemented. The campaign remains deliberately
unrun at 0/20 until Tom supplies exact capped spend authorization. Hosted-product and demand claims
remain deferred, and nobody has been contacted.**

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
  fingerprinting, patch artifact, bounded schema-1.1 JSON report, schema-1.0 backward replay that
  regenerates commands and revalidates archive/tree identities, and successful-generation
  token/latency metadata. The
  controller now builds `pristine tree + exactly one revalidated candidate`, records the resulting
  executed-tree digest, and requires the staged read-only Docker volume to match before pytest runs.
- JUnit retrieval now uses a separate inspected local-tmpfs result volume kept alive by a bounded
  no-network, non-root anchor. The controller bounds and parses the copied bytes, and still treats
  both JUnit and stdout as forgeable hostile evidence.
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
- The v0.2 selection is frozen only after a hash-locked PyArrow worker ran inside an inspected,
  immutable, network-disabled container with no inherited environment, read-only inputs/root,
  non-root execution, dropped capabilities, and bounded CPU/memory/PIDs/output/time. The pinned
  500-row audit quarantined 64 rows; the selected 20/20 are mechanically clean. Issue text remains
  labeled `dataset_snapshot_at_pinned_commit`, `chronology_unproven`, and
  `historical_public_contamination_exposed`; no stronger chronology claim is made.
- The causal wheel dependency executor now accepts only a strict plan path; creates fresh, distinct,
  exactly labeled local-tmpfs input, wheelhouse, and dependency volumes with byte and inode quotas;
  pins one immutable runner image ID; runs only the fixed source-free download and offline-install
  commands; records bounded phase results; and attests the unchanged wheelhouse and installed tree.
  Its nominal typed handle is revalidated before every read-only verifier mount and keeps cleanup
  ownership in the executor context.
- The canonical dependency execution receipt is bounded below 1 MiB and has a strict independent
  loader/verifier plus bundled/public schema. Verification recomputes and cross-binds the plan,
  requirements, policy, volume quotas/labels, image, command/config hashes, phase outcomes, causal
  sequence, tree, typed-handle identity, and cleanup contract instead of trusting readiness booleans.
  The receipt deliberately records `campaign_readiness_changed: false`.
- Real local Docker canaries passed the reviewed `six==1.17.0` PyPI wheel download, offline install,
  direct import, typed read-only verifier borrow, and a separate input-volume inode exhaustion check
  that failed with `ENOSPC` under the declared quota. Cleanup left no owned dependency resources.
  These are local infrastructure checks, not historical case preparation or benchmark results.
- `reproassert benchmark replay-v02-case` consumes one canonical self-hashed bundle, reacquires the
  exact commit/tree/archive, rebuilds an embedded hash-locked wheel plan, verifies the installed
  dependency tree and immutable image ID, reruns the candidate with network disabled, and emits a
  bounded replay-result commitment. It cannot invoke a model provider.
- The capability-gated differential evaluator passed a real local Docker fixture under the frozen
  schedule `base, fixed, fixed, base, base, fixed`: all three base executions produced the same
  intended failure and all three fixed executions passed. It revalidates one candidate, attests both
  candidate-applied trees, requires exact target JUnit evidence, hashes/redacts raw fixed output, and
  can bind a typed dependency receipt/plan/tree/image.
- The v0.2 application issuer promotes dataset evidence only from the nominal Docker-bound parser
  handoff, never a raw receipt or host-native preparation object. The production runner binds all 20
  rendered requests, exact provider/model/adapter pricing, caps, approval bytes, tool revision,
  campaign/cohort/preregistration, and a single-ledger claim before provider-capable work.
- L2 publication requires a mechanical fail-to-pass differential, executed candidate-on-fixed,
  fix-minus, base-plus, and preregistered decoy controls, plus two distinct authorized reviewers.
  A deterministic third reviewer is required only on disagreement. No missing or inconclusive
  control can be published as L2.
- Protected `main` includes the validation controls at merge commit
  `6abbed9ade57934bbdc75afa250800acc355003d` (PR #20). That public milestone passed Python 3.10 and
  3.14, distribution/clean-install, Docker, schema, Ruff, and mypy checks.
- Public proof site and canonical report schema are live over HTTPS at
  <https://atomics-hub.github.io/reproassert/>. The deployed desktop/mobile surface has no detected
  horizontal overflow, overlap, console errors, or warnings.
- GitHub rulesets require pull requests, six path-aware CI contexts, linear history, and immutable `v*`
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
- Leak-audited dataset selection: **20/20 frozen**; prospective issue chronology remains unproven.
- Prepared dependency and hidden-fix evaluator packages: **0/20 authentic scored case packages**.
  The provider-free dataset transaction has authentically materialized and freshly rederived 20/20
  safe projections locally, and v0.2 exact-object source preparation is now supported. The remaining
  source/dependency/hidden-fix package evidence and genuine reviewer assignments do not yet exist.
  The issuer, runner, replay, controls, and schemas are implemented, but no paid campaign ran.
- Exact-object source receipts: **20/20 accepted and independently reverified locally**; private
  receipts are not a public index and have not changed the frozen campaign prerequisite.
- Independently validated or maintainer-accepted tests: **0**.
- Maintainers willing to use it again: **0**.
- L1 plausible fail-to-pass public benchmark results: **0/20 measured**.
- Complete model cost across successful and failed generation attempts, warm runtime, and hosted
  runner COGS: **not measured**. A verified-candidate report does not capture aborted attempts.
- Model/provider spend for the validation campaign: **$0**. CI used the repository's public-runner
  workflow only for the coherent PR gates; no paid service was purchased.
- Paid pilots, qualified trials, and MRR: **0**.

## Next validation slice

1. Treat v0.2.0 as validation-ready tooling, not as benchmark-success evidence; retain v0.1.0 as an
   immutable historical release and require the same exact tag-source gate for every later release.
2. Ask Tom for one explicit capped authorization artifact only after the 20 private case packages,
   request bindings, pricing snapshot, and campaign freeze pass offline verification.
3. Run the 20-case campaign without inspecting hidden fixes in generation, finalize only through the
   causal-control and reviewer-consensus gate, and publish failures as well as successes.
4. Prepare maintainer-validation packets from accepted candidates, but contact nobody without Tom's
   separate exact outreach approval.
