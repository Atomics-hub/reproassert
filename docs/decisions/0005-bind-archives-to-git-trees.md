# 0005 — Bind source archives to reconstructed Git trees

Status: accepted on 2026-07-10

## Context

A codeload URL containing a commit SHA and a SHA-256 of the downloaded tarball prove which bytes the
controller received. They do not independently prove that those bytes represent the Git tree named
by the commit. A checkout, worktree, or `git archive` would introduce additional trust in local Git
configuration, filters, hooks, untracked files, export attributes, and VCS metadata.

The execution workspace must also contain no `.git` directory/file, object database, refs, remote
configuration, linked-worktree metadata, later commits, symlinks, or submodule checkout.

## Decision

- Resolve and record one full 40-hex commit SHA.
- Fetch its root tree OID from GitHub's bounded unauthenticated Git-database commit endpoint. Do not
  request a full diff for an already-resolved SHA.
- Download the tar.gz only from the fixed codeload host, with redirects, proxies, and authentication
  disabled and strict byte limits.
- Manually extract regular files/directories only into a private directory. Reject links, special
  files, traversal, collisions, canonical `.git` aliases, and independent member/file/directory,
  per-file, total-byte, path, and component limits.
- Rewalk through no-follow directory descriptors. Recompute Git blob/tree SHA-1 object IDs from the
  accepted bytes and executable bit, and require the reconstructed root tree to match the commit
  metadata before source context or generation.
- Also record a versioned canonical SHA-256 tree digest over directories and files. This is a second
  content identity, not a replacement for Git's commit-to-tree relationship.
- Replay requires the newly downloaded archive SHA-256 to match the report, repeats the commit-tree
  check, and compares the canonical tree digest when the original report recorded one.
- Benchmark source receipts and their index are preparation artifacts only. Verification must obtain
  the commit tree independently from the frozen manifest/base SHA; an archive and receipt cannot
  authenticate one another. A campaign must separately freeze the receipt-index digest.

## Consequences

Tracked symlinks, submodules/gitlinks, Git LFS pointer expansion, export-altered archives, or other
trees that cannot be represented by the strict regular-file policy fail closed as unsupported
preparation. They are not flattened or silently omitted.

The design still trusts GitHub's API and codeload service, DNS/TLS and the CA store, the controller
host, parser/runtime correctness, and Git's SHA-1 object identity. It is not independent
multi-source provenance or a signed supply-chain attestation.
