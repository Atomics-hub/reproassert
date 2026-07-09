# ReproAssert project goal

Build and publicly launch ReproAssert as a trustworthy open-source product that turns GitHub
issues into verified failing reproduction candidates, validates real maintainer demand, and creates
a credible path toward a hosted business capable of reaching $10,000 MRR.

## Non-negotiable gates

- A public GitHub issue and exact source SHA produce one controller-owned pytest candidate, a
  replay command, a patch, and a machine-readable report.
- Untrusted code runs only in a real sandbox boundary. Missing sandbox means refusal, never a
  native fallback.
- The live CLI may claim only collection or repeatable failure on the buggy base. A hidden-fix
  differential plus blinded semantic review is required for benchmark success.
- Continue the product bet only if the frozen 20-case benchmark reaches at least 6 semantically
  valid successes, median warm runtime is under 10 minutes, and cost has a measured path below
  roughly $1 per valid success.
- Hosted/business validation additionally requires one independently validated or
  maintainer-accepted test and three maintainers willing to use the product again.

This file records the durable objective. [PROJECT_STATUS.md](PROJECT_STATUS.md) records current
evidence without upgrading the claim.
