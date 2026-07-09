## What changed

Describe the narrow product or engineering outcome.

## Verification

List the exact commands run and the relevant result. Include a fixture or regression test when behavior changed.

## Trust checklist

- [ ] Untrusted issue/repository content is treated as data, never controller instructions.
- [ ] The change does not expose host secrets, credentials, the Docker socket, or unrelated files to sandboxed code.
- [ ] Network, resource, timeout, output, and cleanup behavior remains explicit where relevant.
- [ ] User-visible claims are bounded to evidence produced by the implementation or benchmark.
- [ ] Documentation and machine-readable output remain consistent with behavior.

## Release note

State the user-visible change, or write `Not user-visible`.
