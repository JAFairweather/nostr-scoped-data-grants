# SPEC-PROPOSALS: evolving NIP-DA (Scoped Data Grants)

Six proposals that address the weaknesses in DESIGN-REVIEW.md. Each is a
self-contained, PR-sized unit with: the problem, a concrete spec delta (proposed
SPEC.md language / tags / constructions), reference-implementation changes
against `nipxx.mjs`, test and interop assertions to add, migration and
compatibility notes, and a **ready-to-paste Claude Code prompt**.

Suggested PR order: **P1 → P2 → P4 → P6 → P3 → P5.** P1/P2/P4/P6 only add or
clarify (safe). P3 is a mechanism change that stays wire-compatible. P5 is an
experimental parallel kind, not a mutation of `30440`.

The Claude Code prompts assume you run them from inside the repo. Each is scoped
to exactly one PR and tells the agent to update SPEC.md, `nipxx.mjs`, add tests,
and — where relevant — keep `go/main.go` in interop lockstep.

---

## P1 — Normative grant-author verification

**Addresses:** Weakness 1 (bearer keys), partial. **Effort:** S. **Risk:** low.
**Back-compat:** fully compatible; promotes existing implementation lore to a
normative rule.

### Problem

Security 6 already requires verifying that a `kind:30440` replacement's signer
matches its `a`-tag publisher. The symmetric check on the **grant** side is only
implementation lore: a `kind:440` rumor whose authenticated author (the seal
pubkey) differs from the `a`-tag publisher is a *re-wrap* — a grantee re-gifting
a key it holds — not a first-party grant. `receiveGrants` already exposes
`author`, but nothing normative says what to do with it. Note this check cleanly
distinguishes the **sanctioned** delegation mechanism (a derived-scope sub-grant,
where the sub-issuer publishes its *own* `30440`, so author == a-tag publisher)
from the **unsanctioned** one (raw key re-wrap, where they differ).

### Spec delta

Add to the Data Grant section:

> ### Grant authentication
>
> The authenticated author of a grant is the `pubkey` of its NIP-59 **seal**
> (`kind:13`), recovered during unwrapping. Clients MUST compare this author to
> the publisher pubkey encoded in the grant's `a` tag
> (`30440:<publisher-pubkey>:<scope-id>`).
>
> - If they are **equal**, the grant is a first-party grant.
> - If they **differ**, the grant is a *re-wrapped* grant: some grantee has
>   re-delivered a scope key it holds. A re-wrapped grant is cryptographically
>   indistinguishable from key exfiltration. Clients MUST NOT present a
>   re-wrapped grant as a first-party grant. Clients SHOULD reject re-wrapped
>   grants by default; a client MAY accept one only under an explicit,
>   deployment-defined delegation policy, and MUST surface the distinct author.
>
> Sanctioned onward delegation is performed with **derived scopes** (a sub-issuer
> publishing its own `kind:30440`), for which author and `a`-tag publisher agree
> by construction; see [FUTURE / delegation].

### Reference implementation (`nipxx.mjs`)

- In `receiveGrants`, add `rewrapped: rumor.pubkey !== publisher` to each grant
  record (alongside the existing `author`).
- In `latestGrants` (or a new default filter in `addressBook`), exclude
  `rewrapped` grants unless an `{ allowRewrapped: true }` option is passed.
- Keep `author`/`rewrapped` on the record so a policy layer can decide.

### Tests

Add to `smoke.mjs` (local + live): Bob, holding a first-party grant from Alice,
re-wraps the scope key to Carol (author = Bob, a-tag publisher = Alice).
Assert: Carol's `receiveGrants` marks it `rewrapped: true`; Carol's default
`addressBook` omits it; with `{ allowRewrapped: true }` it appears and still
decrypts. Add the mirror assertion to `interop.mjs` so Go and JS agree on the
author field.

### Migration

None. Existing first-party grants are unaffected (`rewrapped: false`). Any
deployment relying on informal re-wrap acceptance opts in explicitly.

### Claude Code prompt

```
Implement Proposal P1 (normative grant-author verification) in this repo.

1. SPEC.md: add a "Grant authentication" subsection under the Data Grant
   (kind:440) section stating that clients MUST compare the seal author to the
   a-tag publisher, MUST NOT present re-wrapped grants (author != publisher) as
   first-party, and SHOULD reject them by default with an explicit-policy escape
   hatch. Reference derived scopes as the sanctioned delegation path.
2. nipxx.mjs: in receiveGrants, add `rewrapped: rumor.pubkey !== publisher` to
   each grant record. Make addressBook (and latestGrants where appropriate) drop
   rewrapped grants unless an { allowRewrapped: true } option is passed. Do not
   remove the existing `author` field.
3. smoke.mjs: add assertions for a Bob->Carol re-wrap — Carol sees rewrapped:true,
   default addressBook omits it, allowRewrapped surfaces and decrypts it. Keep
   both --local and live paths green.
4. interop.mjs / go/main.go: expose the grant author in the Go reader too and add
   one cross-impl assertion that both implementations agree on author identity.
Run `npm run smoke:local` and `npm run interop` and make them pass. Keep the
diff minimal and match the existing code style.
```

---

## P2 — Anti-rollback content sequence

**Addresses:** Weakness 6 (freshness/rollback). **Effort:** S. **Risk:** low.
**Back-compat:** additive tag; old readers ignore it.

### Problem

Content updates do not bump `v` (which tracks rotation only). A grantee talking
to a single withholding relay can be pinned to an older, validly-signed `30440`
with no signal a newer one exists. The only freshness evidence today is the
`updated_at` field *inside* the payload (invisible until decrypted) plus
`created_at` compared across relays (requires the client to actually query more
than one relay).

### Spec delta

Add a relay-visible, signed, per-scope monotone sequence to `kind:30440`:

```json
"tags": [
  ["d", "<scope-id>"],
  ["v", "<scope-key-generation>"],
  ["u", "<update-seq>"]
]
```

> - `u`: a strictly increasing integer, bumped on **every** publish of this scope
>   (both content updates and rotations), independent of `v`. Because it is a
>   signed tag it is visible to relays without decryption, letting a client detect
>   that a served copy is older than one it has already seen. `u` MUST be strictly
>   greater than the `u` of any prior event for the same `(pubkey, d)`.
>
> Freshness rules for grantees:
> - Clients SHOULD fetch a scope from at least two of the publisher's NIP-65
>   write relays and accept the event with the highest `(u, created_at)`.
> - Clients SHOULD persist a per-scope high-water mark `(v, u)` and MUST NOT
>   downgrade to an event whose `(v, u)` is lower than the stored mark; a lower
>   value indicates relay rollback and the client SHOULD warn and/or try other
>   relays.

### Reference implementation (`nipxx.mjs`)

- `publishScope`: accept/track a `seq`, emit `["u", String(seq)]`. Add a small
  helper `nextSeq(prev)` so callers (and the Grant Index `issued` record) can
  carry the last `u` per scope.
- `fetchScope`: query is unchanged, but add optional `{ relays: N }` fanout in
  `liverelay.mjs` (`query` merges results across relays, dedupes by id, keeps
  max `(u, created_at)`).
- Add `highWater` param to `fetchScope`: return `{ status: 'rollback' }` if the
  best event's `(v, u)` is below the caller's stored mark.
- Persist `(v, u)` into the Grant Index `received` entries (`v` already present;
  add `u`).

### Tests

`smoke.mjs`: publish scope at u=1, then u=2; a fetch that (simulated) only sees
u=1 after having recorded u=2 returns `status: 'rollback'`. Multi-relay path:
publish u=2 to relay A only, u=1 to relay B; fanout fetch returns u=2.

### Migration

`u` is additive. Readers without P2 ignore the tag and behave as today. The
Grant Index gains an optional `u`; absence means "unknown, accept newest."

### Claude Code prompt

```
Implement Proposal P2 (anti-rollback content sequence) in this repo.

1. SPEC.md: add a "u" tag to kind:30440 — a strictly increasing per-(pubkey,d)
   integer bumped on every publish (content update AND rotation), independent of
   v. Add freshness rules: multi-relay fanout preferring max (u, created_at), and
   a persisted per-scope high-water (v,u) that clients MUST NOT downgrade below.
2. nipxx.mjs: emit ["u", seq] in publishScope; add nextSeq helper; add optional
   highWater arg to fetchScope returning { status:'rollback' } on downgrade;
   carry u in the Grant Index received/issued entries and the to/from adapters.
3. liverelay.mjs: add multi-relay fanout to query that merges by id and keeps the
   event with max (u, created_at).
4. smoke.mjs: add rollback-detection and fanout assertions (--local and live).
5. Keep go/main.go reading the u tag so interop stays green.
Run npm run smoke:local and npm run interop; keep them passing. Minimal diff.
```

---

## P4 — Incremental grantee inbox

**Addresses:** Weakness 4 (discovery scaling). **Effort:** S. **Risk:** low.
**Back-compat:** fully compatible; pure client optimization.

### Problem

`receiveGrants` re-scans and re-unwraps *all* inbound `kind:1059` wraps every
call. The intrinsic limit (grants can't be distinguished from NIP-17 DMs at the
relay) is fine and should be documented. The avoidable cost is that the scan is
non-incremental even though relays support `since`, and the Grant Index already
holds every accepted grant as a warm cache.

### Spec delta

Add to "Updates, rotation, and revocation" (client guidance, non-normative):

> Grantees SHOULD treat the Grant Index (`kind:10440`) `received` list as the
> authoritative warm cache for the address book, and scan raw `kind:1059` wraps
> only incrementally — with a `since` filter anchored to the newest wrap already
> processed — to discover *new* grants. A full wrap re-scan is required only on
> cold recovery from the private key alone. Grantees cannot filter grants from
> other gift-wrapped messages at the relay (the inner kind is encrypted); this
> is an intended property of NIP-59 and bounds the incremental scan to messages
> newer than the last checkpoint.

### Reference implementation (`nipxx.mjs`)

- `receiveGrants(relay, secret, { since } = {})`: pass `since` into the `1059`
  query; default `since` to `undefined` (full scan) so behavior is unchanged
  unless a checkpoint is supplied.
- Return (or let callers derive) a `checkpoint` = max `created_at` of wraps seen,
  to persist for the next call.
- `addressBook`: accept `{ index, since }` — start from the Grant Index
  `received` entries, then merge in newly-discovered grants since the checkpoint,
  then dereference. Fall back to full scan when no index/checkpoint is given.

### Tests

`smoke.mjs`: after building an address book and checkpointing, issue one new
grant; assert the incremental `receiveGrants({ since })` returns exactly the new
grant, and the merged address book contains both old and new without a full
re-scan (assert query filter carried `since`).

### Migration

None; `since` is optional. Existing callers keep full-scan semantics.

### Claude Code prompt

```
Implement Proposal P4 (incremental grantee inbox) in this repo.

1. SPEC.md: add non-normative client guidance that grantees SHOULD use the Grant
   Index received list as a warm cache and scan kind:1059 wraps incrementally
   with a `since` checkpoint, full re-scan only on cold recovery. State plainly
   that grants are indistinguishable from DMs at the relay (NIP-59 property).
2. nipxx.mjs: add an optional { since } to receiveGrants (passed into the 1059
   query); return/derive a checkpoint (max created_at seen). Update addressBook
   to accept { index, since }, seed from Grant Index received entries, merge new
   grants since checkpoint, then dereference. Preserve current behavior when no
   options are passed.
3. smoke.mjs: assert incremental fetch returns only the new grant and the merged
   book is complete; assert the 1059 query used `since`. --local and live green.
Run npm run smoke:local. Minimal diff, existing style.
```

---

## P6 — Metadata-hardening profile

**Addresses:** Weakness 7 (metadata/correlation). **Effort:** S–M. **Risk:** low.
**Back-compat:** compatible; opt-in behaviors + one cheap default.

### Problem

Gift-wrap hides the grant graph from a single relay, but timing/traffic
correlation, longitudinal `d`-tag tracking ("scope X updated 47 times"), and
size-bucket leakage remain. Several cheap defenses exist and are worth
collecting into one normative-ish profile.

### Spec delta

Add a "Metadata-hardening profile" subsection to Security and privacy:

> Deployments handling sensitive scopes SHOULD adopt the following. Each is
> independent; a client MAY implement any subset.
>
> 1. **Rotate the `d` tag on key rotation.** Because rotation already re-grants
>    every survivor with a fresh `a` tag, the publisher MAY assign a new opaque
>    `d` at the same time at **no extra cost**, breaking a relay's ability to
>    correlate a scope's update history across generations. (The old address
>    becomes a stranded tombstone; publish an empty replacement under the old `d`.)
> 2. **Fetch jitter.** Grantees SHOULD delay first fetch after receiving a grant
>    by a random interval, and SHOULD decouple fetch timing from wrap-delivery
>    timing, to defeat wrap↔fetch correlation (Security 4).
> 3. **Read-relay separation.** Grantees SHOULD fetch `30440` events via their own
>    NIP-65 read relays rather than directly from a relay known to also observe
>    the publisher's writes, where a choice exists.
> 4. **Size padding to coarse buckets.** Publishers MAY pad scope payloads to
>    fixed coarse sizes (on top of NIP-44's own padding) so that field-level
>    content changes do not produce distinguishable size deltas.
> 5. **Decoy updates.** Publishers MAY publish content-preserving `30440`
>    replacements on a randomized schedule so that update timing does not reveal
>    real edits.

### Reference implementation (`nipxx.mjs`)

- `rotateScope({ ..., newScopeId })`: optional — when supplied, publish the new
  generation under `newScopeId`, tombstone the old `d`, and emit grants carrying
  the new `a`. Update the Grant Index `issued` entry's `scope`.
- Add `padTo(payload, bucketBytes)` helper (pad the JSON with an ignored field to
  a bucket boundary before `symEncrypt`).
- Add `jitterFetch(fn, maxMs)` convenience wrapper.

### Tests

`smoke.mjs`: rotation-with-new-`d` — assert survivors get a grant with the new
`a`, the old `d` resolves to an empty tombstone, and `observerView()` (from
`relay.mjs`) shows the scope's `d` changed across generations. Padding: assert
two differently-sized payloads produce equal ciphertext length after `padTo`.

### Migration

`d`-rotation and padding are opt-in per publish. The default path is unchanged.
Note that `d`-rotation interacts with P2's high-water mark (a new `d` is a new
scope identity, so the high-water resets for it) — document this in both.

### Claude Code prompt

```
Implement Proposal P6 (metadata-hardening profile) in this repo.

1. SPEC.md: add a "Metadata-hardening profile" subsection under Security and
   privacy with the five items: d-tag rotation at key rotation (free re-grant
   piggyback + old-d tombstone), fetch jitter, read-relay separation, size
   padding to coarse buckets, and decoy updates. Note the interaction with P2's
   high-water mark when d changes.
2. nipxx.mjs: add optional newScopeId to rotateScope (publish under new d,
   tombstone old d, grants carry new a, update Grant Index issued.scope); add
   padTo(payload, bucketBytes) and jitterFetch(fn, maxMs) helpers.
3. smoke.mjs: assert d-rotation gives survivors the new a and leaves an empty
   tombstone at the old d (use relay.mjs observerView to show d changed); assert
   padTo equalizes ciphertext length for two payloads. --local green.
Run npm run smoke:local. Minimal diff.
```

---

## P3 — Multi-device publisher consistency

**Addresses:** Weakness 5 (multi-device). **Effort:** M. **Risk:** medium.
**Back-compat:** wire-compatible; changes how `v` is chosen and adds an index
merge rule.

### Problem

Three concurrent-device hazards: (a) two devices rotate to the same `v+1` with
different keys; (b) survivors end up holding the losing key and silently go
`stale`; (c) the replaceable Grant Index is last-write-wins, so a device's edits
can be clobbered.

### Spec delta

Three coordinated changes.

**(a) Lamport generation.** Redefine `v` selection:

> When rotating, the publisher MUST set the new `v` to
> `max(all v ever observed for this scope across the publisher's own devices and
> relays) + 1`, not simply `local_v + 1`. This is a Lamport counter: it does not
> prevent a concurrent collision but ensures monotonicity once devices sync.

**(b) Deterministic winner + reconciliation.** Since `30440` is addressable, only
one event survives replacement per `(pubkey, d)`:

> If two rotations collide on the same `v`, NIP-01 addressable replacement leaves
> exactly one surviving `30440` (highest `created_at`, then lowest `id`). Its
> scope key is authoritative. A grantee whose grant decrypts the surviving event
> is current; a grantee whose grant fails (MAC error) is `stale` and MUST be
> re-granted. On its next index sync a publisher device MUST detect survivors
> whose last-issued `(v, key)` does not match the authoritative surviving event
> and re-issue grants for the authoritative key (a reconciling re-grant).

**(c) Mergeable Grant Index.** Replace blind last-write-wins with a merge:

> The Grant Index is a **mergeable** structure. `issued` entries are keyed by
> `scope`; `received` entries by `a`. Each entry carries a `mtime` (unix seconds,
> the last local modification). To merge two index versions, take the union of
> keys and, per key, keep the entry with the greater `mtime` (ties broken by the
> greater `v`, then lexicographically greater `key`). Before publishing, a client
> MUST load the current published index, merge its local state into it, and
> publish the merge — never a blind overwrite. Deletions are represented as
> tombstone entries (`{ ..., deleted: true, mtime }`) so a merge cannot resurrect
> a removed grant.

### Reference implementation (`nipxx.mjs`)

- Add `mtime` to every `issued`/`received` entry (in the `to*Entry` adapters).
- Add `mergeGrantIndex(a, b)` implementing the union+max-mtime rule with tombstones.
- Change `saveGrantIndex` to `load → mergeGrantIndex(published, local) → publish`.
- `rotateScope`: set `next = max(knownGenerations) + 1`; after re-granting, record
  authoritative `(v, key)` in the issued entry.
- Add `reconcile(relay, publisherSecret, index)`: for each issued scope, fetch the
  authoritative `30440`, and if a survivor's issued key ≠ authoritative key,
  re-grant. Return the updated index.

### Tests

`smoke.mjs` (local is enough for determinism): simulate two devices — publish two
`30440` under the same `d` and same `v` with different keys; assert exactly one
survives, a survivor holding the losing key reads `stale`, and after `reconcile`
the survivor reads `ok`. Index merge: two divergent index versions (one adds a
grantee, one revokes another) merge to the correct union without loss; a
tombstoned entry is not resurrected.

### Migration

Existing single-device deployments are unaffected: `max(known)+1` reduces to
`local+1` when there is one device, and `mergeGrantIndex(published, local)` with
no divergence equals the old overwrite. The `mtime`/`deleted` fields are additive;
pre-P3 indexes (no `mtime`) are treated as `mtime: 0` (always lose to a dated
entry, which is the safe default on first upgrade).

### Claude Code prompt

```
Implement Proposal P3 (multi-device publisher consistency) in this repo.

1. SPEC.md: (a) redefine rotation's new v as max(all observed v for the scope)+1
   (Lamport); (b) specify the deterministic addressable winner (max created_at,
   then min id), that losing-key grantees are stale and MUST be reconciled, and a
   reconciling re-grant on index sync; (c) make the Grant Index mergeable —
   issued keyed by scope, received keyed by a, each with mtime; merge = union,
   per-key max mtime (tie: max v, then greater key), tombstones {deleted:true} to
   prevent resurrection; publishing MUST load+merge+publish, never blind overwrite.
2. nipxx.mjs: add mtime to to*Entry adapters; add mergeGrantIndex(a,b) with
   tombstones; make saveGrantIndex load-merge-publish; set rotation v to
   max(known)+1 and store authoritative (v,key) in the issued entry; add
   reconcile(relay, publisherSecret, index) that re-grants survivors whose key
   != authoritative. Treat missing mtime as 0.
3. smoke.mjs (--local): assert single 30440 survives a same-v collision, a
   losing-key survivor is stale then ok after reconcile, and two divergent index
   versions merge without loss and don't resurrect tombstones.
4. Keep go/main.go and interop.mjs green (Go must at least read mtime-bearing
   indexes without breaking).
Run npm run smoke:local and npm run interop. This is a medium change — keep the
merge logic well-commented and match existing style.
```

---

## P5 — Attenuation via per-field key trees (v2 track)

**Addresses:** Weaknesses 1, 2, 3 — the north star. **Effort:** L. **Risk:**
construction change. **Back-compat:** ships as a **new experimental kind**
(`31440`), not a mutation of `30440`; both coexist.

### Problem

One symmetric key over one payload means no attenuation: you cannot grant "these
three fields, no re-delegation" cryptographically, and revocation must rotate the
whole scope. FUTURE.md's "attenuation north star" wants a grantee to derive a
*narrower* capability that is verifiable against the chain.

### Construction

Two complementary mechanisms, each for the direction it actually fits.

**A. Per-field key tree (attenuation of decryption — passive scopes).**
A scope has a random 32-byte **root key** `K`. Each field `f` is encrypted under a
derived subkey:

```
K_f = HKDF-Expand(PRK = K, info = "nipda/v2/field:" || f, L = 32)
```

The `31440` payload encrypts each field independently under its `K_f` (a NIP-44
payload per field), with a cleartext-to-holder manifest of field names. A grant
conveys **a subset of subkeys** `{K_f}` (or, for a full grant, `K` itself, from
which any `K_f` derives). Properties:

- **Attenuation works.** Giving `{K_email, K_tel}` lets the holder decrypt only
  those fields; HKDF-Expand is one-way, so subkeys never reveal `K` or sibling
  subkeys. A leaf can be granted strictly less than the granter holds.
- **Per-field revocation works and is cheap.** Rotate one field's subkey
  (per-field generation), re-encrypt only that field, re-grant only that field's
  survivors — O(field grantees), not O(scope grantees). This directly relieves
  Weakness 3.
- **Onward attenuation works.** A grantee holding `{K_email, K_tel}` can re-wrap
  only `{K_email}` downstream — narrower by construction.
- **Honest limit:** subkeys are still bearer tokens (a malicious holder can share
  what it holds), so cryptographic *containment of a malicious leaf* remains
  impossible — but the leaf can never obtain *more* than granted, which is the
  attenuation half of Weakness 1/2.

**B. Macaroon-style caveats (attenuation of authority — request/provider
direction).** For FUTURE.md's "scoped request → provider → response" flow there is
an online verifier (the provider), so caveats fit where key trees do not:

```
root_token   = HMAC(root_secret, "nipda/v2/req")
attenuated   = HMAC(prev_token, serialize(caveat))   // one-way; holders can only narrow
```

The provider verifies the caveat chain at fulfillment time. This is the right
tool for delegating *authority to act* (Nact/Nvoy), as opposed to the right to
*decrypt* — keep the two mechanisms distinct and documented as such.

### Spec delta (new, parallel)

Add an experimental section "NIP-DA v2: attenuable scopes (`kind:31440`)"
defining: the root-key/subkey derivation (mechanism A) with the exact HKDF
`info` strings; the per-field manifest and per-field `v_f` generation tags; grant
content carrying a `subkeys` map instead of a single `scope_key`; and a note that
mechanism B (caveats) applies to the request direction (cross-reference FUTURE).
Explicitly state `31440` coexists with `30440` and is opt-in; clients advertise
support out of band.

### Reference implementation

New file `nipxx-v2.mjs` (do **not** entangle with the v1 lib): `deriveFieldKey(K,
field)`, `publishAttenuableScope`, `grantFields` (subset), `fetchAttenuableScope`
(decrypt only held fields), `rotateField`. Add a `regrant.mjs`-style prototype
proving: subset grant decrypts only its fields; onward re-wrap can only narrow;
per-field rotation strands only that field's revoked holder.

### Tests

New `smoke-v2.mjs`: field-subset grant decrypts exactly the granted fields;
attempting a non-granted field fails; per-field rotation revokes one field
without disturbing others; onward attenuation cannot widen. Keep it `--local`
first; add a live/interop pass once the Go side implements `31440`.

### Migration

Purely additive — a new kind and a new lib file. `30440` is untouched.
Applications adopt `31440` where they need attenuation and keep `30440` for
flat scopes. Recommend shipping P5 behind an app-level feature flag.

### Claude Code prompt

```
Implement Proposal P5 (attenuable scopes via per-field key trees) as an
EXPERIMENTAL parallel track — do NOT modify kind:30440 or nipxx.mjs semantics.

1. SPEC.md: add a clearly-marked experimental section "NIP-DA v2: attenuable
   scopes (kind:31440)". Define K_f = HKDF-Expand(K, "nipda/v2/field:"+f, 32),
   a per-field-encrypted payload with a holder manifest, per-field generation
   tags v_f, and grant content carrying a subkeys map. State it coexists with and
   does not replace 30440. Add a short note that macaroon-style caveats
   (token' = HMAC(token, caveat)) are the companion mechanism for the
   request/provider direction (cross-ref FUTURE.md), distinct from decryption
   attenuation.
2. New file nipxx-v2.mjs (independent of nipxx.mjs): deriveFieldKey, 
   publishAttenuableScope, grantFields (subset), fetchAttenuableScope (decrypt
   only held fields), rotateField. Reuse nostr-tools nip44 exactly as nipxx.mjs
   does; HKDF via nostr-tools/@noble hkdf.
3. New smoke-v2.mjs (--local): subset grant decrypts only granted fields; a
   non-granted field cannot be read; rotateField revokes one field only; onward
   re-wrap can only narrow (never widen).
Run node smoke-v2.mjs --local. This is a v2 experiment: keep it isolated, and
label it experimental in SPEC.md. Do not touch the v1 smoke/interop paths.
```

---

## Cross-cutting notes for whoever opens these PRs

- **Keep interop honest.** P1, P2, P3 touch fields the Go implementation reads;
  each prompt tells the agent to keep `go/main.go` and `interop.mjs` green. Land
  the JS + spec change and a Go-read update together, or the interop suite (a key
  credibility asset) goes red.
- **`v` vs `u` vs `v_f`.** After P2 and P5 there are three counters with distinct
  jobs: `v` = scope-key rotation generation (P1/P3), `u` = per-scope content
  sequence for rollback detection (P2), `v_f` = per-field rotation generation
  (P5). Name them consistently in SPEC.md to avoid confusion.
- **Order matters for the high-water mark.** P2 introduces a persisted `(v, u)`
  high-water; P6's `d`-rotation changes scope identity (resetting that mark). If
  both land, add one sentence to each cross-referencing the other.
- **Nothing here fixes physics.** Retained plaintext, best-effort erasure, and
  bearer-token re-sharing of whatever a holder legitimately holds are inherent.
  The proposals bound and detect these, and make attenuation/revocation
  finer-grained — they do not claim to eliminate them. Keep the SPEC's honest
  framing.
