# Project status

Last updated: 2026-07-09

## Current verdict

**GO for the bounded Python/pytest feasibility experiment. Hosted product and demand claims are
deferred.**

## Verified now

- Installable Python 3.10+ package and `reproassert` CLI.
- Strict canonical GitHub issue intake, exact 40-hex commit resolution, bounded archive download,
  and traversal/collision/link/bomb-resistant extraction.
- One controller-chosen test path and function, strict JSON generator protocol, and AST policy
  rejection for obvious false-reproduction and execution patterns.
- Explicit opt-in OpenAI Responses adapter at a fixed endpoint, plus the provider-neutral command
  protocol and manual-candidate path. API-key presence alone never initiates a paid request.
- Hardened Docker verification with no host bind mount, no inherited environment, network off,
  read-only root/workspace, non-root user, capability drop, no-new-privileges, and CPU, memory,
  PID, file, tmpfs, timeout, log, and output limits.
- Candidate collection plus three clean targeted runs, exact failure classification, normalized
  fingerprinting, patch artifact, bounded JSON report, replay that regenerates commands, and
  successful-generation token/latency metadata.
- Public self-owned [issue #1](https://github.com/Atomics-hub/reproassert/issues/1) at exact commit
  `7b03e8f7f4b7312f1785e7853892efa123e48699` reaches `repeatable_base_failure` in 3/3 clean
  containers; a fresh report replay matches the fingerprint in another 3/3 runs. The local fixed
  source passes. This is infrastructure proof, not benchmark accuracy.
- Frozen public benchmark manifest: 20 historical cases across 10 repositories; five-case smoke
  subset; strict schemas and validator.

## Evidence still missing

- Historical benchmark results: **0/20 run**.
- Semantically valid benchmark reproductions: **0/20 measured**.
- Independently validated or maintainer-accepted tests: **0**.
- Maintainers willing to use it again: **0**.
- Complete model cost across successful and failed generation attempts, warm runtime, and hosted
  runner COGS: **not measured**. A verified-candidate report does not capture aborted attempts.
- Paid pilots, qualified trials, and MRR: **0**.

## Next exact build slice

1. Publish the verified CLI milestone and live self-owned issue-to-test demo.
2. Add a durable benchmark attempt ledger that counts provider spend and time for failures as well
   as candidates that reach verification.
3. Run the frozen five-case smoke cohort with evaluator/oracle isolation and publish every outcome.
4. Continue to all 20 only if setup reliability and semantic precision justify the spend.
5. Prepare outreach packets; do not contact maintainers without separate exact approval.

The active project goal is intentionally not marked complete while these validation gates remain.
