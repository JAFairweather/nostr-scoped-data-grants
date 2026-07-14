# Future directions (non-normative)

Ideas that extend the Scoped Data Grants primitive beyond the current SPEC.
These are exploratory — recorded to guide design, not part of the draft NIP.

## Scoped requests: a request that is a grant *and* an enact

The SPEC frames the flow as one-directional: a keyholder publishes an encrypted
**scope** and issues a **grant** to a recipient, who dereferences it live. The
recipient perceives; the granter decides.

But the same three event kinds compose into a *request*, initiated by the party
that wants data, aimed at a **named provider**. A scoped-data request is two
things at once:

1. a **grant** — the requester grants the provider scoped, revocable access to
   the request itself (the query and whatever context the provider needs to
   fulfill it), and
2. an **enact request** — it asks the provider to *act*: assemble the data,
   decide whether to approve, and return it.

The provider, on approval, replies with **another scope** — a grant back to the
requester:

```
  requester → [ request  = grant(params) + enact-request ] → provider
  provider  → [ approve + assemble ]                        → requester
  provider  → [ response = grant(data) ]                    → requester
```

### Why it matters at the protocol level

- **Perceive and act are the same exchange, two directions.** A data request is
  an action (proposed, approved, fulfilled); fulfilling it produces a grant
  (scoped, live, revocable). The "approval" a provider gives is a signature
  authorizing assembly-and-return — the same shape as the human approval in
  [nact](https://github.com/JAFairweather/nact).
- **Revocation stays with the provider.** Because the response is a scope, the
  provider can rotate the response grant's key and revoke what it returned —
  symmetric with a granter revoking a recipient today.
- **Providers become first-class.** Named and discoverable over NIP-05, a
  provider can publish which scopes it will fulfill and on what terms. Requests
  **chain**: use provider A's returned scope as a param-grant in a request to
  provider B, with revocation propagating along the chain.

### What it would need

A request event kind (or a tag convention over the existing grant kind) that
marks a grant as *soliciting fulfillment* and names the target provider, plus a
response that references the request. Whether this is a new kind or a profile
over the current three is an open question — deliberately left for
implementation experiments before any normative change.

Companion note (the action side): [nact/DESIGN.md → "Two directions the
primitive wants to grow"](https://github.com/JAFairweather/nact/blob/main/DESIGN.md).
