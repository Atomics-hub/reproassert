# ADR 0014: exact-image campaign freeze and request cap audit

Status: accepted

## Decision

The v0.2 scored lane first uses `reproassert benchmark prepare-v02-execution-freeze` to bind the verified
20-case preparation receipt, deny-network exact-image runtime manifest, complete gold-smoke
receipt, preregistration and campaign freeze, all 20 exact rendered request hashes, the pricing
snapshot, requested model, and the merged controller Git SHA. The command accepts only the
documented USD 5.00 campaign / USD 0.25 per-case authorization statement with zero overage. It
does not read provider credentials or make a provider call. It emits the exact approval statement
containing its final immutable hash. Only the separate `authorize-v02-execution` command accepts
that statement, and its timestamp must be strictly later than the prepared freeze.

Before writing an authorization, the controller independently computes a worst-case reservation
for every complete canonical outbound request body using the same conservative byte-as-token bound
as the scored runner. The committed body includes instructions, schema, model/config, and input;
pricing only `provider_request.input` is insufficient and rejected.
Every case must fit USD 0.25 and the sum must fit USD 5.00. The artifact records all 20
reservations so the cap decision is inspectable. One authorization covers one campaign and one
attempt per case.

The earlier source-context policy could place as many as 5,000 paths in a request manifest. Two
prepared cases exceeded the approved per-case reserve because of path bytes alone. The revised
policy still bounds traversal at 5,000 regular files, but caps the JSON-encoded rendered manifest at
128 KiB while retaining every selected source file. Its policy hash is explicit in the execution
freeze. This changes request hashes and the source-context policy commitment, so old preparations
and preregistrations cannot be silently reused.

## Consequences

- Provider execution remains impossible from the freeze command itself.
- The current f69-prepared envelopes are not authorizable: they are not at the execution
  controller merge SHA, and cases 004 and 005 exceed the approved per-case reserve. Authentic
  rerenders under the bounded policy reserve 199,274 and 196,853 micro-USD respectively.
- A successor preparation and preregistration must be generated after merge, then independently
  verified before this command can produce an execution freeze.
- Gold-smoke infrastructure failures remain in the 20-case denominator; binding a complete smoke
  receipt does not convert them into semantic successes.
