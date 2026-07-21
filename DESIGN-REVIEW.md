# Design Review: NIP-DA — Scoped Data Grants

*Reviewer notes on `nostr-scoped-data-grants`. Scope: SPEC.md, the JS reference
implementation (`nipxx.mjs`), and FUTURE.md. Companion to SPEC-PROPOSALS.md,
which turns the weaknesses below into PR-ready spec deltas.*

---

## Verdict

This is a strong, principled design and unusually disciplined engineering for a
draft NIP. The central idea is a genuine contribution, the reuse of existing
primitives is correct, and the honesty of the security section is itself a
quality signal. The weaknesses are not mistakes — they are the honest
consequences of one deliberate bet (symmetric bearer keys), and they cluster in
predictable places. Everything below is calibrated for someone who already
understands the protocol.

## What is right

**The core inversion.** Replacing N² rotting copies of contact data with N
self-maintained authoritative records — where the address book is an *emergent
view* of capabilities that dereference live — is the correct primitive. It is
the same move that DNS made over hosts files and that capability systems made
over ACLs: stop copying state, hand out dereferenceable references. Framing the
address book as "a set of (pointer + decryption right) capabilities" is exactly
the right mental model and it is carried consistently through the spec and code.

**No new cryptography.** Using the NIP-44 v2 payload format with a random 32-byte
scope key fed directly in as the `conversation_key` (skipping ECDH) is clean and
correct. NIP-44's per-message keys come from `HKDF-Expand(conversation_key,
nonce)`, and HKDF-Expand only requires its input to be a cryptographically strong
pseudorandom key — which a CSPRNG-generated 32-byte key is. You inherit
authenticated encryption, version negotiation, and the padding scheme (which is
what bounds size leakage to relays) for free, and you introduce zero new
constructions into the ecosystem. This is the right kind of conservative.

**No relay changes.** Everything is plain NIP-01 addressable-event semantics.
Zero deployment barrier is rare and valuable; it means the protocol is real
today rather than contingent on relay adoption.

**Two independent implementations with live interop.** JS and Go sharing nothing
but the spec, cross-decrypting each other's scopes and detecting each other's
rotations on public relays, is the strongest possible evidence that the wire
format is actually unambiguous. Most draft NIPs never reach this.

**Correct small decisions.** Opaque `d` tags; the `v` generation counter so a
grantee detects rotation *without* a failed decrypt; unsigned rumors sealed and
gift-wrapped for grant-graph privacy plus deniability; the seal/rumor pubkey
equality check in `giftUnwrap`; keying "latest grant" on `generation` rather than
`created_at` (robust against timestamp fuzzing); the self-encrypted Grant Index
as the recovery root. These are all the choices an expert would make.

## Where it is weak

The weaknesses below all trace back to one design bet: **a scope is protected by
a single symmetric key that is handed to grantees as a bearer token.** That bet
buys O(1) updates and zero relay changes. What it costs is enumerated here.

### 1. Symmetric scope keys are bearer tokens — the load-bearing weakness

A grantee who holds a scope key can re-share it with anyone, out of band, and
this cannot be prevented cryptographically. The `author !== publisher` re-wrap
check that `receiveGrants` exposes is honest-*client* enforcement only: a
malicious grantee simply pastes the base64 key into a channel your code never
sees. Consequently `expiration`, `redelegate:false`, and "scoped disclosure"
itself are all social/client-layer guarantees against a cooperative grantee, not
cryptographic guarantees against a malicious one. The security model against a
malicious grantee is essentially: *you can stop sending them future updates.*
That is worth stating plainly, because applications built on top (especially
agent delegation) can otherwise imply containment the primitive does not provide.

### 2. No attenuation, and it is the thing the design most wants

FUTURE.md already pins this precisely: you can have cryptographic revocation
cascade (key re-wrap) **or** attenuation (derived scopes), but not both, and
derived-scope revocation is runtime-mediated rather than cryptographic. Because
one symmetric key covers the whole payload, a grantee cannot be given "these
three fields, read-only, no re-delegation" in a way that is enforced by math. For
the AI-agent delegation use case this is the ceiling. The fix is a construction
change (per-field key trees / macaroon-style caveats), correctly deferred to a v2
track — see Proposal P5.

### 3. Revocation is coarse and bursty

Rotation cost is O(remaining grantees): revoking one person from a `basic` scope
shared with 300 contacts means one re-encrypt plus **300 fresh gift-wraps**. That
is a visible burst to relays (a correlation signal in its own right) and it
requires an intact `issued` index to even compute the survivor set. The
"structure scopes by revocation churn" guidance is the right mitigation but it
pushes real modeling burden onto every client author. Per-field key trees (P5)
also shrink this cost by letting you rotate one field instead of a whole scope.

### 4. Grantee-side discovery does not scale cleanly

`receiveGrants` pulls *all* `kind:1059` gift wraps addressed to the user and
unwraps every one. Because NIP-17 DMs share kind 1059 and the inner kind is
encrypted, you cannot filter grants from DMs server-side — an active user with
thousands of inbound wraps pays an O(all wrapped messages) decrypt cost to
rebuild the address book. The intrinsic part (can't distinguish grants from DMs
at the relay) is the price of NIP-59 privacy and should just be documented. The
fixable part is that the scan is *non-incremental*: relays support `since`, and
the Grant Index can serve as a warm cache, so steady-state cost can be near-zero
(Proposal P4).

### 5. Multi-device publisher consistency has a real gap

`v` is a per-scope counter incremented on rotation with no coordination, and the
Grant Index is a replaceable last-write-wins event. Two devices rotating
concurrently both choose `v+1` with different keys; survivors can end up holding
the losing key and silently fall to `stale`. Concurrent index edits on two
devices race and can drop a device's grants entirely. For the mainstream use case
(everyone has a phone and a laptop) this needs an explicit answer: a Lamport-style
`v`, a deterministic data-set winner, mandatory survivor reconciliation, and a
*mergeable* Grant Index (Proposal P3).

### 6. Deletion and freshness are best-effort by construction

"Replacement is destruction on conforming relays" holds only for relays that do
not retain history; paid/archival relays keep the old ciphertext, and NIP-09 is
advisory. Separately, content *updates* do not bump `v`, so a grantee talking to
a single withholding relay can be pinned to a stale-but-validly-signed version
with no signal that a newer one exists — the only freshness evidence is the
`updated_at` claim *inside* the payload plus `created_at` across relays. A signed,
relay-visible monotone sequence plus a persisted high-water mark and multi-relay
fanout closes the detectable-rollback gap (Proposal P2). True erasure is
physically unavailable and should stay honestly labeled.

### 7. Metadata leakage is the soft underbelly for a privacy protocol

Gift-wrap hides the grant graph from a *single* relay, but (Security 4) an
observer that sees both the wrap delivery and the subsequent fetch of a specific
`30440` address can correlate. Add a stable opaque `d` tag that lets a relay
count "scope X updated 47 times," the padded-but-bucketed size class, and update
timing, and a global or multi-relay observer recovers much of what the protocol
exists to hide. Several cheap hardening moves exist — notably rotating the `d`
tag *at rotation time*, which is free because everyone is being re-granted anyway
(Proposal P6).

## How to read the proposals

The proposals in SPEC-PROPOSALS.md are ordered by leverage-over-effort, not by
weakness number:

| # | Addresses | Type | Effort | Back-compat |
|---|-----------|------|--------|------|
| P1 | 1 (partial) | normative clarification | S | compatible |
| P2 | 6 | additive tag + client rule | S | compatible |
| P4 | 4 | client/impl optimization | S | compatible |
| P6 | 7 | privacy profile | S–M | compatible |
| P3 | 5 | consistency mechanism | M | mostly compatible |
| P5 | 1, 2, 3 | v2 construction (key trees) | L | new kind track |

P1, P2, P4, P6 are safe, near-term PRs that only add or clarify. P3 is a
medium-risk mechanism change that is still wire-compatible with existing events.
P5 is the north-star construction and should ship as an *experimental parallel
kind*, not a mutation of the current one.
