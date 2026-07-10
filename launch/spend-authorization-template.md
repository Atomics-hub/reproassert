# Scored-campaign spend authorization

Status: **template only — no spend authorized**

Complete every field from a frozen campaign and a current primary pricing source before asking for
approval. Never infer approval from an API key, an earlier experiment, a budget discussion, or a
repository permission.

## Proposed experiment

| Field | Required value |
| --- | --- |
| Campaign ID | `<campaign-id>` |
| Preregistration SHA-256 | `<64-hex>` |
| Campaign-freeze SHA-256 | `<64-hex>` |
| Tool commit | `<40-hex>` |
| Provider and exact model | `<provider/model-version>` |
| Pricing source and effective time | `<primary-source URL and RFC 3339 time>` |
| Frozen cases | `20` |
| Maximum submitted candidates | `1 per case; 20 total` |
| Maximum provider calls | `1 per case; 20 total; zero retries` |
| Maximum provider timeout | `<seconds per case>` |
| Maximum output tokens | `<tokens per call>` |
| Reserved worst case | `$<amount> per case` |
| Hard case cap | `$<amount> per case` |
| Hard campaign cap | `$<amount> total` |
| Expected-case estimate | `$<amount> total, nonbinding` |
| Non-model metered services | `<none, or exact service and cap>` |

## Mandatory abort conditions

The controller must stop before another provider call when any of these occurs:

- the explicit campaign identity, tool commit, model, price snapshot, input, or cap changes;
- a provider call has no exact terminal usage record or its attributable cost is unknown;
- a prior attempt is unreconciled, duplicated, or has an unmatched reservation;
- known spend plus active reservations plus the next reservation exceeds the campaign cap;
- the one-candidate generation barrier, sandbox, evaluator capability, or private-output boundary
  fails closed;
- a login, 2FA, CAPTCHA, payment, terms, suspicious-account, or destructive prompt appears; or
- a retry, extra trajectory, fallback model, or additional paid service would be needed.

## Exact approval sentence

Replace every placeholder. Approval is valid only for this one immutable experiment:

> I authorize ReproAssert campaign `<campaign-id>` at preregistration `<sha256>` and tool commit
> `<git-sha>` to make at most 20 one-shot calls to `<provider/model-version>`, with no retries, a
> hard cap of `$<case-cap>` per case and `$<campaign-cap>` total. Stop on unknown cost or any changed
> input. This does not authorize maintainer contact or any other paid service.

Record the exact approval text or immutable reference in the private campaign policy. Do not put
credentials, billing identifiers, or private account data in the public repository.

