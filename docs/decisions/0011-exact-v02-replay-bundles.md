# ADR 0011: exact v0.2 replay bundles

Status: accepted — 2026-07-10

## Decision

Publish one canonical, self-hashed replay bundle for every v0.2 case that submits a candidate. The
bundle binds the exact repository and buggy SHA, codeload archive hash, Git root tree, canonical
source tree, candidate bytes, expected normalized failure fingerprint, repeat count, a
publisher-declared controller Git revision, and either an explicit dependency-free mode or the
complete canonical wheel plan plus installed-tree and immutable-image commitments. The declared
revision is retained as unauthenticated publisher provenance; replay does not claim it matches the
installed controller.

`reproassert benchmark replay-v02-case <bundle>` reacquires source from the exact commit, rebuilds
the candidate overlay, and reruns it in Docker. For dependency-bearing cases it permits network only
inside the fixed source-free wheel-download phase, verifies every wheel hash, installs offline,
attests the installed tree, and mounts that tree read-only into network-disabled pytest containers.
The plan must name ReproAssert's packaged trusted runner tag; hostile bundles cannot select another
locally present image. The command has no provider adapter and writes a schema-backed, bounded,
self-hashed replay result with collection and repeated-run evidence only when the observed outcome
and fingerprint match the bundle.

## Why

A bare pytest command is not reproducible evidence when source acquisition, dependency closure, and
runner identity are part of the result. A complete VM image would be harder to inspect, expensive to
publish, and still architecture-specific. The bundle keeps the durable contract small while forcing
the controller to reconstruct and re-attest every executable input.

## Consequences

- Bundles are hostile unsigned data; hashes detect internal mismatch but do not authenticate an
  author.
- The publisher-declared controller Git revision is not authenticated against an installed wheel;
  release attestations are the separate mechanism for authenticating official distribution source.
- Immutable Docker image IDs are architecture-local. A publisher must build and attest a bundle per
  supported architecture rather than pretending one local image ID is portable.
- PyPI bridge egress remains constrained by fixed pip behavior and post-download hashes, not a
  destination network ACL.
- Ordinary `reproassert issue` and `reproassert replay` remain dependency-free.
