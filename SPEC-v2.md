# NIP-XX v2 — Attenuable Scoped Data Grants (per-field key trees)

`experimental` `parallel track` — this document does **not** modify or replace
[SPEC.md](SPEC.md). It defines a second, opt-in construction (`kind:31440`)
that coexists with `kind:30440`; both can serve the same publisher at once,
and clients advertise v2 support out of band. Applications adopt `31440`
where they need attenuation and keep `30440` for flat scopes. Reference
implementation: [`nipxx-v2.mjs`](nipxx-v2.mjs); tests: `npm run smoke:v2`.

## Why a v2 exists

The v1 construction protects a scope with **one** symmetric key handed to
grantees as a bearer token. That deliberate bet buys O(1) updates and zero
relay changes, and it costs exactly what the design review enumerates
(DESIGN-REVIEW.md, weaknesses 1–3): no attenuation — a grant is the whole
scope or nothing, so "these three fields only" cannot be granted in a way
enforced by math; and coarse revocation — expelling one grantee rotates the
whole scope and re-wraps every survivor, O(remaining grantees) at once.
FUTURE.md's "attenuation north star" names the goal: a grantee holds — or
derives — a capability strictly narrower than the granter's, verifiable and
enforced cryptographically.

v2 reaches the attenuation half of that north star by splitting the scope's
encryption per field under a derived key tree. It deliberately introduces
**no new cryptography**: the one derivation primitive it uses, HKDF-Expand
over SHA-256, is the primitive NIP-44 already applies to every message key,
and every ciphertext remains an ordinary NIP-44 v2 payload.

## Event kinds

| kind    | description                                | encryption                         |
| ------- | ------------------------------------------ | ---------------------------------- |
| `31440` | Attenuable Scoped Data Set (addressable)   | per-field, under derived subkeys   |
| `442`   | Attenuable Data Grant (unsigned rumor)     | NIP-59 seal + gift wrap            |

Kind numbers are placeholders pending assignment. The v2 grant is a **new
rumor kind** rather than a versioned `kind:440` payload, and this is
load-bearing for coexistence: v1 readers gate their inbox scan on the rumor
kind *before* parsing content, so they skip `442` rumors structurally — a
`kind:440` rumor without a `scope_key` member would instead crash a
conforming v1 reader mid-scan. Relays cannot tell the difference either way:
both grant kinds travel inside `kind:1059` gift wraps, indistinguishable
by design.

## The key tree

A scope has a random 32-byte **root key** `K` — generated exactly like a v1
scope key, and a valid HKDF pseudorandom key for the same reason v1 may feed
a raw scope key to NIP-44 (RFC 5869 requires only a cryptographically strong
PRK; a CSPRNG output is one). Everything else derives from `K` by
HKDF-Expand over SHA-256, with domain-separated `info` strings:

```
K_f(g)   = HKDF-Expand(PRK = K, info = "nipda/v2/field:" || f || ":" || g, L = 32)
K_m      = HKDF-Expand(PRK = K, info = "nipda/v2/manifest",                L = 32)
label_f  = lowercase-hex( HKDF-Expand(PRK = K, info = "nipda/v2/label:" || f, L = 8) )
```

- `f` is the field name. Field names MUST match `[a-z0-9_-]+` (the vCard
  lowercase convention v1 already recommends), which keeps every `info`
  string unambiguous — `:` cannot occur inside a name.
- `g` is the field's **per-field rotation generation** `v_f`, a decimal
  integer starting at 1. The generation participates in the derivation:
  that is what makes per-field rotation possible. (A generation-free
  `K_f = HKDF(K, field)` would be a pure function of the root — rotating
  one field would then require rotating `K`, i.e. the whole scope, which is
  the v1 cost this construction exists to avoid.)
- `K_m` is the **manifest key**, held by every grantee of the scope; it
  rotates only when `K` does.
- `label_f` is the field's opaque **wire label** (16 hex chars) — the name
  under which the field's ciphertext and generation travel on the wire, so
  that **field names never appear relay-visible**. Labels are derived, not
  stored: the publisher recomputes them from `K` at will, and because they
  derive from `K`, *every label changes when the root rotates* — severing a
  relay's longitudinal per-field trail at each root rotation, the same
  severance the v1 metadata-hardening profile buys for the scope itself by
  moving the `d` tag.

Security of the tree rests on HKDF-Expand (HMAC-SHA-256) being a PRF:
outputs under distinct `info` strings are computationally independent, and
no set of outputs reveals the PRK or any output outside the set. Holding
any subset of `{K_f(g)}` therefore reaches neither `K`, nor `K_m`, nor any
sibling field, nor any other generation of the same field. The tree is one
level deep by design — see "Rejected: deeper trees" below.

## Attenuable Scoped Data Set (`kind:31440`)

An addressable event; one scope, one event, per-field ciphertexts inside:

```json
{
  "kind": 31440,
  "pubkey": "<publisher-pubkey>",
  "tags": [
    ["d", "<scope-id>"],
    ["v", "<root-key-generation>"],
    ["u", "<content-seq>"],
    ["vf", "<label>", "<field-generation>"],
    ["vf", "<label>", "<field-generation>"]
  ],
  "content": "{\"m\": \"<nip44-ct under K_m>\", \"f\": {\"<label>\": \"<nip44-ct under K_f(g)>\", ...}}"
}
```

- `d`, `v`, `u` keep their v1 semantics **verbatim**: `d` an opaque scope
  id; `v` the **root** rotation generation (bumped only when `K` rotates);
  `u` the per-scope content sequence, strictly increasing across every
  publish, feeding the same `(v, u)` high-water freshness rule as v1
  ("Freshness and rollback detection" applies unchanged, with `31440`
  substituted). There are three counters in v2 and they keep the epic's
  naming discipline: `v` = root rotation generation, `u` = content
  sequence, `v_f` = per-field rotation generation.
- One `vf` tag per field carries the field's current generation under its
  opaque label. This is what lets a holder — root or attenuated — detect a
  single field's rotation from the event header alone, without decrypting;
  the metadata price is stated plainly below ("What a relay sees").
- `content` is cleartext JSON with two members: `m`, the **manifest**
  ciphertext, and `f`, the per-label field-ciphertext map. Each value is an
  ordinary NIP-44 v2 payload with the respective derived key used directly
  as the conversation key — v1's construction, per field.

### The manifest

The manifest is the scope's *cleartext-to-holder* table of contents:
readable by every grantee (full or attenuated — everyone holds or derives
`K_m`), ciphertext to relays. Decrypted:

```json
{
  "name": "Personal",
  "updated_at": 1751904000,
  "fields": {
    "email": { "label": "<label_email>", "v": 2 },
    "tel":   { "label": "<label_tel>",   "v": 1 }
  }
}
```

It maps each field *name* to its wire label and current `v_f`. A reader
decrypts the manifest first, then exactly the fields its keys reach. A
holder whose subkey generation is below the manifest's `v_f` knows —
deterministically, without a MAC failure — that the field rotated past it.

### Per-field payloads

Each field's plaintext is the JSON value of that field (string, array,
object — the same values v1 puts in its `fields` map, one per ciphertext).
NIP-44's padding applies per field; publishers who care about size classes
MAY additionally pad individual values coarsely (v1's metadata-hardening
item 4, applied per field). Removing a field from a publish removes it from
manifest and wire map; its subkey holders simply see it gone.

## Attenuable Data Grant (`kind:442`)

An unsigned rumor, sealed and gift-wrapped per NIP-59 exactly as v1 grants
are — same inbox, same privacy argument, same discovery costs and cursor
discipline. The rumor:

```json
{
  "kind": 442,
  "pubkey": "<granter-pubkey>",
  "created_at": 1751904000,
  "tags": [
    ["a", "31440:<publisher-pubkey>:<scope-id>", "<relay-hint>"],
    ["v", "<root-key-generation>"]
  ],
  "content": "<json, one of the two shapes below>"
}
```

**Full grant** — conveys the root; every subkey, label, and future per-field
generation derives from it:

```json
{ "scope_name": "Personal", "root_key": "<base64-32-bytes>" }
```

**Attenuated grant** — conveys the manifest key and an explicit subset of
field subkeys, each pinned to its generation:

```json
{
  "scope_name": "Personal",
  "manifest_key": "<base64-32-bytes>",
  "subkeys": {
    "email": { "v": 2, "key": "<base64-32-bytes>" },
    "tel":   { "v": 1, "key": "<base64-32-bytes>" }
  }
}
```

The attenuated grantee can decrypt the manifest and exactly the granted
`(field, generation)` pairs. Nothing else is reachable from what it holds —
not by client policy but by the one-wayness of the derivation. This is the
central property of v2: **a grant can be strictly narrower than what the
granter holds, and the narrowing is enforced by math.**

### Grant authentication (carried over from v1)

v1's rule applies verbatim: the authenticated author of a grant is the
NIP-59 seal pubkey; clients MUST compare it to the `a`-tag publisher.
Equal → first-party. Different → a **re-wrapped** grant — some holder
re-delivering key material — which clients MUST NOT present as first-party
and SHOULD reject by default, accepting it only under an explicit
delegation policy that surfaces the distinct author.

What changes in v2 is not the rule but the blast radius: a re-wrapping
holder can only pass along keys it holds, so an onward re-wrap can **narrow
but never widen** — a `{email, tel}` holder can re-wrap `{email}`, and
nobody can re-wrap a field or a root they were never granted. Re-wrap
remains unsanctioned exfiltration-shaped delegation, exactly as in v1;
derived scopes (a sub-issuer publishing its own scope) remain the sanctioned
path (FUTURE.md, "Delegation chains").

### Effective capability (merging grants)

Grants accumulate: after a per-field rotation a survivor holds its original
attenuated grant plus a one-field re-grant. Readers MUST reduce grants to
one effective capability per `(publisher, scope, author)`:

- a grant at a higher root generation (`v` tag) supersedes all grants below
  it — those died with the old root;
- within a root generation, a full grant subsumes subkeys; otherwise
  subkeys union per field, highest `v_f` winning;
- re-wrapped grants are excluded by default (above), and key material from
  distinct authors is never blended into one capability.

## Dereference semantics

A reader fetches the current `kind:31440` (verifying, as in v1, that the
event's signer matches the `a`-tag publisher), applies v1's freshness rules
to `(v, u)` against its persisted high-water mark (`rollback` on downgrade),
then:

- event `v` above the capability's root generation, or manifest MAC
  failure → the root rotated past this capability: **stale**, exactly v1's
  supersession signal. (A capability's manifest key always decrypts the
  manifest of its own root generation — so an attenuated holder gets
  deterministic staleness signals for the whole scope and per field.)
- otherwise, per field in the manifest: subkey held at the manifest's
  `v_f` → decrypt → **ok**; subkey held at a lower `v_f` → **stale** (this
  field rotated past the holder); no subkey → **locked** — the field is
  cryptographically unreadable, and clients MUST present it as *not
  granted*, never as empty or missing data.

## Rotation and revocation

Two levels, two costs, one rule of thumb — rotate the smallest thing that
cuts off the party being revoked:

**Per-field rotation** (revoke an *attenuated* holder of field `f`): bump
`v_f`, republish (the event's `u` bumps as on every publish; `v` does not),
re-grant the new `K_f(g+1)` to the field's surviving *attenuated* holders.
Root holders derive the new subkey from the bumped manifest and need
nothing. Attenuated holders of other fields are untouched. Cost:
**O(that field's attenuated holders)** — this is the answer to weakness 3's
O(scope grantees) re-wrap burst, and it composes: structure a scope so the
churny field is its own leaf, and revocation churn stops touching anyone
else.

**Root rotation** (revoke a *full* holder, or fully expel anyone): fresh
random `K`, `v` bumped by v1's Lamport rule (max observed + 1), per-field
generations restart at 1 (`v_f` is scoped to its root generation), every
survivor re-granted — full holders get the new root, attenuated holders
their new subkeys. Everything re-keys because everything derives from `K`;
all wire labels change with it, breaking the relay's per-label trail. Cost:
O(all survivors), unavoidable — the revoked party held, or could reach,
everything.

A field-revoked holder retains, until the next **root** rotation, the
manifest key — it can still read field *names*, labels, generations, and
`updated_at`, though none of the rotated field's content. Fully expelling a
party from scope *metadata* therefore requires a root rotation; publishers
for whom manifest visibility is itself sensitive should treat per-field
rotation as attenuation of content access, not as expulsion.

Revocation notices (v1 `kind:441`) and scope deletion/tombstoning carry
over unchanged in shape; a v2 tombstone is a `kind:31440` with an empty
field set under a fresh, never-granted root.

## What a relay sees

Everything v1 leaks, plus per-field *structure* under opaque names: the
number of fields, each label's ciphertext size, and each label's `vf`
rotation counter. Because NIP-44 renonces every ciphertext, **every** field's
ciphertext changes on **every** publish — a relay cannot tell which field's
content changed from ciphertext deltas alone; what it newly gets is
per-label size trajectories and per-label rotation timing. Field *names*
and values never appear. Root rotation re-labels every field, cutting the
longitudinal per-label trail exactly as a v1 `d`-move cuts the per-scope
trail (and a v2 rotation MAY also move `d`, combining both). This is a real,
disclosed metadata cost of attenuation — finer-grained ciphertext structure
in exchange for finer-grained grants — and deployments for which it
dominates should keep such scopes on v1's single-blob construction.

## Companion mechanism: caveats for the request direction (note)

Per-field key trees attenuate the right to *decrypt* — the passive-scope
direction, where no online verifier exists and relays must stay dumb. The
**request/provider** direction of FUTURE.md ("Scoped requests") has the
opposite shape: a named provider *executes* each request, so attenuation of
*authority* fits macaroon-style caveats there:

```
root_token  = HMAC(root_secret, "nipda/v2/req")
attenuated  = HMAC(prev_token, serialize(caveat))    // one-way: holders can only narrow
```

A holder appends caveats ("only scope X", "expires T", "no re-delegation")
and hands the narrowed token on; the provider — the online verifier —
recomputes the HMAC chain and enforces every caveat at fulfillment time.
The two mechanisms are complementary and MUST NOT be conflated: key trees
bound what a holder can *read* with no verifier in the loop; caveats bound
what a bearer can *ask an online party to do*. This document specifies only
the former; caveat profiles belong to the request-direction work
(FUTURE.md) when it lands.

## Security and privacy considerations

1. **What attenuation guarantees.** An attenuated grantee cannot read
   fields outside its grant — against a *malicious* grantee too, since no
   computation on held subkeys reaches `K` or sibling subkeys (PRF
   security of HKDF-Expand). Onward re-wraps can only narrow. This is the
   half of weaknesses 1/2 that cryptography can close, and v2 closes it.
2. **What attenuation does not guarantee.** Every key is still a bearer
   token: a holder can re-share *what it holds* out of band, and no
   protocol sees it happen. Attenuation bounds what an attenuated grantee
   can **decrypt**; it does not contain a malicious holder's re-sharing of
   its own grant. There is **no cryptographic re-delegation control** — a
   narrowing re-wrap cannot be prevented, only rejected by honest readers
   (grant authentication, above) — and **no expiry enforcement**:
   `expiration` remains advisory, honored by honest clients, exactly as in
   v1. Revocation still controls *future* access only; plaintext already
   decrypted is retained by whoever decrypted it. None of v1's honesty
   obligations are relaxed here.
3. **Compromise blast radius.** A leaked subkey exposes one field at one
   generation until that field rotates. A leaked manifest key exposes scope
   metadata (names, labels, generations) until the root rotates. A leaked
   root key exposes the scope's current and future content until the root
   rotates — the same radius as a leaked v1 scope key, with rotation as the
   same remedy. Within one generation there is, as in v1, no forward
   secrecy.
4. **Residual manifest visibility.** Per-field revocation leaves the
   revoked party able to read scope metadata (not content) until the next
   root rotation — see "Rotation and revocation". Clients granting
   attenuated access to metadata-sensitive scopes should say so, or the
   publisher should rotate the root.
5. **Metadata.** See "What a relay sees": per-label sizes and rotation
   counters are a new, disclosed leak class relative to v1's single blob.
   The grant graph keeps v1's protections (NIP-59 wraps, kind
   indistinguishable at the relay).
6. **No new primitives.** Every ciphertext is NIP-44 v2; the only
   derivation is HKDF-Expand over SHA-256, already load-bearing inside
   NIP-44 itself. No construction novel to the ecosystem is introduced.

## Open questions (deliberately unresolved while experimental)

- **Grant Index integration.** v2 capabilities (root keys, subkey sets)
  need `kind:10440` entries and merge rules; entangling the experimental
  track with the v1 index schema before the wire format settles would
  freeze both too early. Until then, v2 grants are recoverable only by
  inbox re-scan.
- **Multi-device publishers.** v1's Lamport/reconcile machinery (P3) is
  carried over only for the root `v`; concurrent per-field rotations from
  two devices (same `v_f`, different derivation epochs — impossible while
  `v_f` derives keys deterministically from a shared `K`, but real once
  devices disagree on generations) need a reconcile story before v2 leaves
  experimental status.
- **Interop.** The Go implementation does not yet read `31440`; the
  cross-implementation pass extends to v2 once it does. Until then the v2
  suite is JS-only (`npm run smoke:v2`), and v1's interop suite is
  untouched.
- **Group leaves.** Fields with correlated churn could share a leaf
  (`"nipda/v2/field:work_contact:g"` covering several vCard properties as
  one JSON object) — expressible today by structuring values; whether
  named groups deserve first-class derivation paths is left to usage.

## Rejected alternatives (recorded so they stay rejected)

- **Deeper / binary key trees (GGM-style subtree grants).** A balanced tree
  over fields would let one key convey a whole subtree. Rejected: contact
  scopes hold a handful of fields with no natural binary order; real grant
  subsets rarely align to subtrees, so granters hand out leaf sets anyway,
  and the tree adds position-encoding complexity for no realized win. The
  flat tree keeps the derivation one `info` string deep; "groups" are
  structured values instead.
- **Independent random leaf keys, wrapped per field in the event.**
  Rotation-flexible, but every event grows a per-field key envelope, full
  grants need the envelope set rather than deriving offline, and root
  holders lose grant-free ride-through of field rotations. Derivation gives
  all three back and matches §P5's construction.
- **Per-grantee payload encryption (per-field HPKE to each grantee).**
  O(grantees × fields) event size — abandons the O(1)-in-grantees event
  that the whole design is built on.
- **Macaroon caveats as the scope-attenuation mechanism.** Needs an online
  verifier; relays must stay dumb and must not learn. Right tool for the
  request direction only (see the companion note).
- **Versioned `kind:440` payloads instead of a new grant kind.** Crashes
  unmodified v1 readers (see "Event kinds") — coexistence by construction
  beats coexistence by careful parsing.
- **Field names / `v_f` in cleartext tags.** Leaks the scope's disclosure
  structure to relays — v1's own argument for opaque `d` tags, applied one
  level down. Opaque derived labels carry the tags instead.
