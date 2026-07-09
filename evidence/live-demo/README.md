# Public self-fixture evidence

Status: verified on 2026-07-09. This is infrastructure proof, not benchmark or demand evidence.

The public issue [Atomics-hub/reproassert#1](https://github.com/Atomics-hub/reproassert/issues/1)
describes the intentionally buggy slug fixture at exact public commit
[`7b03e8f7f4b7312f1785e7853892efa123e48699`](https://github.com/Atomics-hub/reproassert/commit/7b03e8f7f4b7312f1785e7853892efa123e48699).
The same commit supplied the controller used for this run.

## Command

After building the pinned sandbox image, the forward run used:

```console
uv run --frozen --all-extras reproassert issue \
  https://github.com/Atomics-hub/reproassert/issues/1 \
  --commit 7b03e8f7f4b7312f1785e7853892efa123e48699 \
  --generator-command ./examples/deterministic_generator.py \
  --run-base <private-run-directory> \
  --json-output
```

The emitted report was then replayed with a new intake, named volume, and container set:

```console
uv run --frozen --all-extras reproassert replay \
  evidence/live-demo/reproassert-report.json \
  --run-base <private-replay-directory> \
  --json-output
```

## Result

- Forward report: [`reproassert-report.json`](reproassert-report.json)
- Fresh replay: [`replay-report.json`](replay-report.json)
- Candidate patch: [`candidate.patch`](candidate.patch)
- Collection: exit `0`, exactly one intended test collected.
- Forward verification: three of three runs exited `1` with `AssertionError` and the intended
  `duplicate separators remain` symptom.
- Replay verification: three of three fresh runs produced the same normalized failure fingerprint,
  `3c2f8b1273619743a9966fd3ce5f56cafc804b41eff6e7812970041491d1784b`.
- Verification ran in Python 3.12.13 / pytest 9.1.1 on the pinned Docker image with networking off,
  a read-only root and workspace, UID/GID 65532, dropped capabilities, and bounded resources.

The checked-in copies differ from the raw runtime reports only in `replay.display_command`: the
host-local private path was replaced with the equivalent repository-relative evidence path. Replay
ignores that display field and regenerates controller-owned commands.

The deterministic adapter made no model request and incurred no model cost. This self-owned fixture
does not count toward the frozen 20-case historical benchmark, maintainer validation, willingness to
reuse, or the business-demand gates.
