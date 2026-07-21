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
  [Nact](https://github.com/JAFairweather/nact).
- **Revocation stays with the provider.** Because the response is a scope, the
  provider can rotate the response grant's key and revoke what it returned —
  symmetric with a granter revoking a recipient today.
- **Providers become first-class.** Named and discoverable over NIP-05, a
  provider can publish which scopes it will fulfill and on what terms. Requests
  **chain**: use provider A's returned scope as a param-grant in a request to
  provider B, with revocation propagating along the chain.

### A worked instance: channel-authority grants (Nact)

Nact uses exactly this symmetry to bind an approver to a channel. The control
plane's owner **invites** a Director to approve over some channel — that invite is
a *request* for a **channel-authority grant**. The Director **fulfills** it by
issuing a scope back: signed with their key, naming the verified channel and the
scoped authority it carries (`{channel, delivery_proof, authority:{identities,
tiers}, expires}`), gift-wrapped to the runtime's npub. The runtime dereferences
it live and honors approvals over that channel only while the grant is live;
the Director revokes by rotating that one channel's key.

```
  owner    → [ invite = request for channel authority ] → Director
  Director → [ approve + issue channel-authority grant ] → runtime (Nactor)
  runtime  → honors that channel's approvals only while the grant dereferences live
```

So "who may approve over which channel" is *itself* a request-that-becomes-a-grant:
the invite solicits, the acceptance is the returned scope, and revocation is a key
rotation the granter (the Director) owns. See
[nact/docs/threat-model.md → "Channel authority as a scoped grant"](https://github.com/JAFairweather/nact/blob/main/docs/threat-model.md)
and [nact/docs/architecture.md → "Director channel-authority grants"](https://github.com/JAFairweather/nact/blob/main/docs/architecture.md).

### What it would need

A request event kind (or a tag convention over the existing grant kind) that
marks a grant as *soliciting fulfillment* and names the target provider, plus a
response that references the request. Whether this is a new kind or a profile
over the current three is an open question — deliberately left for
implementation experiments before any normative change.

Companion note (the action side): [nact/DESIGN.md → "Two directions the
primitive wants to grow"](https://github.com/JAFairweather/nact/blob/main/DESIGN.md).

## Delegation chains, revocation cascade, and the attenuation north star

What happens when a *grantee* wants to pass narrower access onward — the
`root delegator → sub-issuer → leaf` chain a fleet or a per-user agent
hierarchy needs? A working prototype (nvoy `test/regrant.mjs`, driven against
both the reference lib and a conforming grantee runtime) pins where the current
primitive lands, and the answer splits by mechanism:

**Key re-wrap** — the grantee re-gifts the scope key it holds (a `kind:440`
rumor it authors whose `a` tag still names the root publisher's scope).

- Revocation cascade is **cryptographic**: one root rotation strands every
  holder of the old key at once, including re-wrapped grantees the root
  delegator never knew existed.
- But attenuation is **impossible** (same key ⇒ whole payload), the delegator
  cannot see or revoke an individual re-wrapped grantee, and the mechanism is
  indistinguishable from key exfiltration — which is why conforming grantee
  implementations already **reject** any grant whose rumor author differs from
  the `a`-tag publisher, and why terms-bearing deployments treat
  `redelegate:false` as forbidding exactly this (as an audit term).

**Derived-scope sub-grant** — the sub-issuer publishes *its own* `kind:30440`
(author = publisher, so every conforming receiver accepts) whose payload it
projects — narrowed — from what it read upstream, and grants that onward under
its own terms.

- Attenuation **works** (a payload projection; the leaf never holds the root
  key), per-leaf revocation **works** (rotate the derived key, re-grant
  survivors), and the root chain is untouched by either.
- Revocation cascade is **runtime-mediated, not cryptographic**: rotating the
  root cuts the sub-issuer off, but leaves keep reading the sub-issuer's
  derived scope — its last upstream snapshot — until the sub-issuer rotates it
  away. The **sub-issuer obligation** (a conformance term in the spirit of
  `no_persist` honesty): on finding your source scope `stale`/`missing`,
  rotate your derived scopes with no survivors (optionally tombstone and send
  `kind:441` notices). Staleness is bounded by the sub-issuer's re-read
  interval, plus leaf-grant TTLs as defense in depth.

So today the two halves of "real" delegation live in different mechanisms:
cryptographic cascade without attenuation (re-wrap), or attenuation without
cryptographic cascade (derived scopes). Deployments should use derived scopes
and state the cascade bound honestly.

Two consequences worth promoting toward the draft NIP:

1. **Grant-side author verification.** The Security section already requires
   verifying that a `kind:30440` replacement's signer matches its `a` tag; the
   symmetric check on the *grant* side — a `kind:440` rumor whose author
   differs from the `a`-tag publisher is a re-wrap, not the publisher's grant —
   is currently implementation lore. The reference reader now exposes the
   rumor author on each received grant (`author`) so consumers can make the
   check; a future revision should consider making it normative (reject, or
   surface-and-flag).

2. **The attenuation north star.** The end state wants both halves at once: a
   grantee derives a *narrower* capability from the grant it holds — fewer
   fields, shorter TTL, no further delegation — such that the derived grant is
   verifiable against the chain and dies cryptographically with it (macaroon-
   style caveats, or per-field key trees where a scope key derives per-field
   subkeys). That is a construction change (today's scope key is one symmetric
   key over one payload) and belongs in a v2 exploration, not the current
   draft. Until then, attenuation-by-projection with the sub-issuer obligation
   is the honest, working answer.
