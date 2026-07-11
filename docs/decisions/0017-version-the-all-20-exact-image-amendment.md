# 0017: Version the all-20 exact-image amendment

Status: accepted

## Decision

A fresh gold-smoke run may replace the historical case 014 network infrastructure failure with
semantic-valid evidence. That changes scoring eligibility, so it is preparation protocol v0.2.1,
not a correction to v0.2 and not an official SWE-bench score.

The v0.2.1 capability index is issued only when the verifier recomputes 20 semantic-valid rows and
zero infrastructure failures from the complete runtime manifest, hidden extraction, and gold-smoke
receipt. The v0.2.1 case controller binds that index plus the exact manifest commitment and smoke
receipt. Its dependency-ready count is the verifier-issued evaluator-preflight-ready count; local
image presence is never readiness evidence.

The amendment narrows `psf__requests-1921` from six fail-to-pass checks to one by excluding five
checks that require external network access under the unchanged `network_mode=none` policy. It adds
no checks, changes no pass-to-pass checks, changes no other instance, and leaves the 20-case cohort
and denominator intact. The old/new gold-spec commitments are respectively
`f9cdfa3b0fa7aa8d26a7c4720af36095fe429f098daa5dcea41a436895f63544` and
`8fa460abb6d72fcaa19f3588277216aa8b483eb28e27ea78985cb7e6f6ceb1db`. The original and amended
all-case smoke raw commitments are respectively
`f3f9069c814e4ae02b833a7907def018a5cee74e3080bda291918b6887061d46` and
`717304fd207077211d5e4066737100128d68012c0e6967e9d930d3dcaae3fc19`.

No provider, model, or generated candidate was invoked or inspected to choose the amendment. The
redacted public record is
[`exact-image-amendment-v0.2.1.json`](../../benchmarks/v0.2-draft/exact-image-amendment-v0.2.1.json).
Independent governance review remains pending; the record is preparation evidence, not scoring
authorization.

Legacy v0.2 19/1 capability indexes and wheel-plan case packets remain verifiable. Provider
execution remains disabled for v0.2.1 preparation artifacts. The existing v0.2 preregistration
explicitly rejects 20/0 authority.

## Consequences

- A recommitted count edit, reordered case, substituted manifest, or changed capability file fails
  fresh rederivation.
- No provider call, API credential, hidden path, test name, or raw evaluator log is added to the
  preparation artifacts.
- A later migration must version and bind v0.2.1 through preregistration, campaign freeze,
  authorization, config, scored evaluation, all causal controls, semantic review, and publication
  before case 014 can execute or contribute to a score.
