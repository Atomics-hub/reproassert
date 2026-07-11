# 0014: Frozen instance gold smoke is evaluator-private and provider-disabled

Status: accepted

`reproassert benchmark smoke-v02-instance-runtimes` validates the frozen 20-case SWE-bench
runtime set before candidate generation. The command requires explicit SHA-256 commitments for
both the runtime manifest and evaluator-private gold specs, freshly verifies the hidden extraction
receipt, and runs only the manifest-bound test command (`pytest-v1` or `sympy-bin-test-v1`).

The image pull is a separate, bounded acquisition phase. Workspace preparation and every test
command run with Docker network mode `none`, no credentials, no host bind mount, a read-only root
filesystem, dropped capabilities, and resource limits. No model or provider code is reachable from
this controller.

The canonical private receipt always contains all 20 case rows. A targeted smoke marks the other 19
rows `not_run`; it never shrinks the denominator. Raw hidden patches and raw sandbox output are not
stored. The receipt records only hidden-input commitments and bounded output hashes. Timeouts,
collection/setup failures, output-limit failures, and disabled-network dependencies are
infrastructure failures, not semantic reproductions. In particular, a test that needs public
network access cannot become a semantic pass under the secure profile.

`reproassert benchmark verify-v02-instance-gold-smoke RECEIPT` verifies the canonical self-hash,
redaction claims, result ordering, selection accounting, phase evidence, and the complete
denominator without executing code.
