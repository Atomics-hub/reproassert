# Maintainer validation packet

Status: **template only — no outreach authorized**

Create one copy per candidate only after the scored campaign is finalized. The recipient should be
able to judge the reproduction without trusting ReproAssert, seeing a hidden benchmark fix, or
installing a broad GitHub App.

## Packet contents

- Repository and exact buggy commit: `<owner/repo>@<40-hex>`
- Original issue: `<public issue URL>`
- Candidate patch: `<path or attached bounded diff>`
- Candidate SHA-256: `<64-hex>`
- One-command reproduction: `<sandboxed command>`
- Expected symptom in the candidate: `<bounded text>`
- Observed base consistency: `<N/N and normalized fingerprint>`
- Hidden-fix result, if disclosure is permitted: `<N/N or withheld>`
- ReproAssert report and public aggregate commitments: `<links and SHA-256 values>`
- Environment and limits: `<image digest, Python version, timeout, CPU, memory, network policy>`
- Known limitations: `<setup assumptions, unsupported dependencies, semantic uncertainty>`

The packet must not contain credentials, private evaluator paths, unpublished maintainer data, raw
provider responses, hidden developer tests, or an assertion that mechanical fail-to-pass proves
issue fidelity.

## Five-minute independent check

1. Check out the exact buggy SHA in a disposable environment.
2. Inspect the candidate patch before applying it.
3. Run the supplied sandbox command with network disabled after dependency preparation.
4. Confirm that the observed failure is the issue's intended behavior, not a generic crash,
   unrelated existing failure, timeout, or assertion that can never pass.
5. Optionally rerun on the maintainer's known fix or current branch and record the exact commit.

## Feedback record

Please answer with `yes`, `no`, or `uncertain`, plus one sentence where useful:

1. Does the test trigger the behavior described by the issue?
2. Does its assertion distinguish the intended broken behavior from unrelated failures?
3. Would you accept the test as written? If not, what smallest change is required?
4. Did the one-command reproduction work in the declared environment?
5. Would you use this workflow on another issue?
6. Did it save time compared with writing the first reproduction manually?
7. May ReproAssert publish your validation, repository, and quoted feedback? Publication permission
   is separate from technical validation.

Record the response date, reviewer identity or approved pseudonym, reviewed candidate SHA-256,
reviewed repository commit, verdict, required edits, repeat-use intent, and publication permission.
Silence, a star, a benchmark pass, or a generic compliment is not maintainer validation.

