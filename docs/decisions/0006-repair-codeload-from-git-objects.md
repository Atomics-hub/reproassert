# 0006 — Treat codeload as transport and Git objects as source authority

Status: accepted on 2026-07-10

## Context

The regular-file archive policy in [ADR 0005](0005-bind-archives-to-git-trees.md) bound 16 of the
20 frozen v0.1 cases to their commit trees. It correctly rejected the other four rather than
changing them: one tree contains a gitlink, two contain tracked symlinks, and one uses
`export-subst`, which makes `git archive` rewrite a tracked blob. A codeload archive is useful bulk
transport, but it is not an exact byte-for-byte checkout for every valid Git tree.

Cloning would add a Git executable, configuration, filters, hooks, credential behavior, object
database, and repository metadata to a path that only needs inert source bytes. Flattening links or
accepting export-expanded bytes would instead break the exact-commit claim.

## Decision

- Read the commit's root tree OID from the fixed unauthenticated GitHub Git-database endpoint.
- Fetch one bounded recursive Trees API response. Reject truncation, unsupported modes, missing
  ancestors, path or Unicode/case collisions, canonical `.git` aliases, and any response whose
  entries do not reconstruct every declared subtree and the expected root Git OID.
- Accept only modes `040000`, `100644`, `100755`, `120000`, and `160000`. Serialize API mode
  `040000` as Git's tree-object mode `40000` when reconstructing object IDs.
- Parse codeload as a bounded stream without extracting it. Treat regular-file bytes and symlink
  linknames as exact only when their recomputed Git blob OID equals the tree entry. Missing or
  changed blobs become an explicit repair plan.
- Fetch only the bounded set of planned repair OIDs from a controller-constructed fixed GitHub Blob
  API URL using the raw media type. Do not use URLs returned inside untrusted API data. Use no
  credentials, proxies, or redirects; require the exact declared byte count and Git blob OID.
- Commit separately to the Git root OID, a SHA-256 metadata-manifest digest, and a SHA-256
  content-tree digest over paths, modes, exact bytes, and gitlink identities.
- Materialize only after every referenced blob is verified. Preserve tracked symlinks only when a
  logical multi-hop resolution cannot escape the source root or reach canonical Git metadata.
  Represent a gitlink as an empty directory, like an uninitialized superproject checkout; never
  discover or fetch its remote or commit recursively.
- Keep the workspace private and metadata-free, verify it immediately after materialization, and
  remove it before writing the deterministic benchmark receipt. Preserve the inert codeload archive
  and the separate object-source receipt. This preparation does not run a model and cannot change
  campaign readiness.

## Consequences

The controller can faithfully represent the frozen cohort's tracked symlinks, gitlink boundary, and
unexpanded Git blobs without cloning or executing repository content. A malicious codeload archive
cannot become source authority merely by arriving from the expected URL.

The first implementation deliberately rejects a truncated recursive tree, more than 64 repair paths
or unique repair OIDs, non-UTF-8 paths or symlink targets, unsafe symlink chains, and trees beyond
the fixed entry/blob/byte limits. Gitlinks remain empty; a later dependency or test step may still
fail if a case actually needs initialized submodule content. These are compatibility boundaries,
not reasons to weaken the identity check.

The design still trusts GitHub's commit, tree, blob, and codeload services, DNS/TLS and the system CA
store, Git's SHA-1 object model, the controller runtime, parsers, host filesystem, and operator. The
additional SHA-256 digests detect internal content drift but are not signatures or independent
multi-source provenance.
