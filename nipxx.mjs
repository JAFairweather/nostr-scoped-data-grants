// nipxx.mjs — Permissioned Private Data Sharing (Scoped Data Grants)
// Reference implementation. No dependencies beyond nostr-tools.
//
// Event kinds (placeholders pending assignment):
//   30440  Scoped Data Set   (addressable; content symmetrically encrypted under a scope key)
//     440  Data Grant        (unsigned rumor, delivered via NIP-59 gift wrap)
//   10440  Grant Index       (replaceable; NIP-44 encrypted to self)
//
// Every flow takes a `relay`: any object with publish(event) and query(filter).
// Sync or async both satisfy it — `await` passes plain values through — so the
// in-memory relay (relay.mjs) and the SimplePool adapter (liverelay.mjs) drive
// this single implementation of the wire format.

import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, nip44, verifyEvent } from 'nostr-tools'

export const KIND_DATA_SET = 30440
export const KIND_GRANT = 440
export const KIND_GRANT_INDEX = 10440

// ---------------------------------------------------------------- scope keys

// Web-platform primitives only (crypto, btoa/atob) — this file runs
// unchanged in Node ≥ 20 and in the browser.

// ------------------------------------------------------------------ signers
//
// Every keyholder parameter accepts either a raw 32-byte secret key or a
// *signer*: { getPublicKey(), signEvent(event), nip44Encrypt(pub, pt),
// nip44Decrypt(pub, ct) } — all async. A NIP-07 browser extension maps onto
// this interface directly, so clients never need the raw key in-page.

export function localSigner(sk) {
  const pub = getPublicKey(sk)
  const conv = (pk) => nip44.v2.utils.getConversationKey(sk, pk)
  return {
    getPublicKey: async () => pub,
    signEvent: async (event) => finalizeEvent(event, sk),
    nip44Encrypt: async (pk, plaintext) => nip44.v2.encrypt(plaintext, conv(pk)),
    nip44Decrypt: async (pk, ciphertext) => nip44.v2.decrypt(ciphertext, conv(pk)),
  }
}

const asSigner = (s) => s instanceof Uint8Array ? localSigner(s) : s

// NIP-59, from signer primitives (nostr-tools' nip59 needs the raw key).
// Timestamps are fuzzed up to two days into the past, per the NIP.

/** NIP-59 timestamp-randomization window (seconds): how far into the past
 *  giftWrap backdates `created_at` — and therefore how far *behind* its
 *  checkpoint an incremental inbox scan must reach (see receiveGrants),
 *  since a wrap delivered after a scan may be timestamped up to this much
 *  older than everything that scan saw. One constant, both duties. */
export const WRAP_OVERLAP = 2 * 24 * 60 * 60

const fuzz = () => now() - Math.floor(Math.random() * WRAP_OVERLAP)

async function giftWrap(signer, recipientPub, rumor) {
  rumor.id = getEventHash(rumor)
  const seal = await signer.signEvent({
    kind: 13, created_at: fuzz(), tags: [],
    content: await signer.nip44Encrypt(recipientPub, JSON.stringify(rumor)),
  })
  const ephemeral = generateSecretKey()
  return finalizeEvent({
    kind: 1059, created_at: fuzz(), tags: [['p', recipientPub]],
    content: nip44.v2.encrypt(JSON.stringify(seal),
      nip44.v2.utils.getConversationKey(ephemeral, recipientPub)),
  }, ephemeral)
}

async function giftUnwrap(signer, wrap) {
  const seal = JSON.parse(await signer.nip44Decrypt(wrap.pubkey, wrap.content))
  if (seal.kind !== 13 || !verifyEvent(seal)) throw new Error('bad seal')
  const rumor = JSON.parse(await signer.nip44Decrypt(seal.pubkey, seal.content))
  if (rumor.pubkey !== seal.pubkey) throw new Error('seal/rumor pubkey mismatch')
  return rumor
}

/** A scope key is a random 32-byte symmetric key. */
export const newScopeKey = () => crypto.getRandomValues(new Uint8Array(32))

const b64 = (bytes) => btoa(String.fromCharCode(...bytes))
const unb64 = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0))

// NIP-44 v2 payload format, with the raw scope key used directly as the
// conversation key (no ECDH step). Reuses NIP-44's authenticated encryption,
// versioning, and — importantly for relay-visible size — its padding scheme.
const symEncrypt = (obj, scopeKey) => nip44.v2.encrypt(JSON.stringify(obj), scopeKey)
const symDecrypt = (ciphertext, scopeKey) => JSON.parse(nip44.v2.decrypt(ciphertext, scopeKey))

// ---------------------------------------------------------------- publisher

// Content sequence (SPEC "Freshness and rollback detection"): every publish
// of a scope — content update or rotation — carries a strictly increasing
// `u` tag, independent of `v` (the rotation generation). Being signed and
// relay-visible, `u` lets a grantee recognize a served copy as older than
// one already seen, without decrypting.

/** Next content sequence after `prev` (absent/unknown counts as 0). */
export const nextSeq = (prev) => (Number(prev) || 0) + 1

// Per-process last-emitted `u` per (publisher, scope), so every publish path
// bumps the sequence without threading state — same spirit as the monotonic
// now() below. Spans one session only: across sessions, carry the last `u`
// (e.g. in the Grant Index `issued` entry) and pass `seq` explicitly — the
// strict-monotonicity duty is then the caller's.
const seqs = new Map()

/**
 * Publish (or replace) a Scoped Data Set.
 * `scopeId` should be opaque — semantic names in `d` tags leak disclosure
 * structure to relays. The human-readable name lives inside the ciphertext.
 * `seq` is the content sequence for the `u` tag; when omitted it continues
 * from this process's last publish of the scope. Returns the signed event,
 * the `seq` used (persist it to bump from later), plus whatever receipt the
 * relay's publish produces (e.g. ack counts from LiveRelay).
 */
export async function publishScope(relay, publisherSecret, { scopeId, generation, scopeKey, payload, seq }) {
  const ts = now()
  const signer = asSigner(publisherSecret)
  const scopeRef = `${await signer.getPublicKey()}:${scopeId}`
  if (seq == null) seq = nextSeq(seqs.get(scopeRef))
  seqs.set(scopeRef, seq)
  const event = await signer.signEvent({
    kind: KIND_DATA_SET,
    created_at: ts,
    tags: [['d', scopeId], ['v', String(generation)], ['u', String(seq)]],
    content: symEncrypt({ ...payload, updated_at: ts }, scopeKey),
  })
  const receipt = await relay.publish(event)
  return { event, seq, ...receipt }
}

/**
 * Issue a Data Grant: deliver a scope key to a grantee.
 * The grant is an unsigned rumor, sealed and gift-wrapped per NIP-59 — the
 * relay sees only an ephemeral pubkey delivering an opaque blob to the
 * grantee. The grant graph is precisely what this protocol protects.
 */
export async function grant(relay, publisherSecret, granteePubkey,
                            { scopeId, generation, scopeKey, scopeName, relayHint = '' }) {
  const signer = asSigner(publisherSecret)
  const publisherPub = await signer.getPublicKey()
  const rumor = {
    pubkey: publisherPub,
    kind: KIND_GRANT,
    created_at: now(),
    tags: [
      ['a', `${KIND_DATA_SET}:${publisherPub}:${scopeId}`, relayHint],
      ['v', String(generation)],
    ],
    content: JSON.stringify({ scope_key: b64(scopeKey), scope_name: scopeName }),
  }
  const wrap = await giftWrap(signer, granteePubkey, rumor)
  const receipt = await relay.publish(wrap)
  return { wrap, ...receipt }
}

/**
 * Revoke a grantee from a scope: rotate the key, republish the data under the
 * new key, and re-grant only the survivors. The revoked party keeps whatever
 * plaintext they already decrypted (unavoidable, and honest to say so) but is
 * cut off from all future updates.
 *
 * `newScopeId` (optional) moves the scope to a fresh `d` in the same
 * rotation — metadata hardening at no extra grant cost, since every survivor
 * is re-granted anyway and the new address rides in the same gift wrap as
 * the new key (SPEC "Metadata-hardening profile", item 1). The new
 * generation is published under the new `d` as a NEW scope identity: its
 * content sequence restarts (a continued `u` would re-link, for an
 * observing relay, exactly the histories the move severs), and the old
 * address is stranded behind a deleteScope-style tombstone — empty payload,
 * throwaway key, same bumped generation, the old identity's next `u` — but
 * no NIP-09: the address is abandoned, not deleted. An explicit `seq`
 * applies to that tombstone (the sequence the caller was tracking). The
 * returned `scopeId` is the live identity — fold it into the Grant Index
 * `issued` entry, whose `scope` thereby moves too.
 */
export async function rotateScope(relay, publisherSecret,
                                  { scopeId, generation, payload, scopeName, survivors, seq, newScopeId }) {
  const scopeKey = newScopeKey()
  const signer = asSigner(publisherSecret)
  // Lamport generation (SPEC "Concurrent publisher devices"): the next `v`
  // is max(all v observed for this scope) + 1 — the caller's own record
  // joined with whatever the relay set currently serves — never simply
  // local + 1. On one device the two coincide; across devices this cannot
  // prevent a concurrent collision (the relay may not carry the rival yet)
  // but guarantees generations never move backwards once devices sync.
  const [cur] = await relay.query({
    kinds: [KIND_DATA_SET], authors: [await signer.getPublicKey()], '#d': [scopeId],
  })
  const seenV = Number(cur?.tags.find(t => t[0] === 'v')?.[1] ?? 0)
  const next = Math.max(generation, seenV) + 1
  const liveId = newScopeId ?? scopeId
  // A rotation is also a publish, so `u` bumps too (tracker default, or the
  // caller's explicit seq); the new mark is returned alongside the new key.
  // A moved scope instead starts its sequence fresh — see above.
  const pub = await publishScope(relay, publisherSecret,
    { scopeId: liveId, generation: next, scopeKey, payload, seq: newScopeId ? undefined : seq })
  if (newScopeId)
    await publishScope(relay, publisherSecret,
      { scopeId, generation: next, scopeKey: newScopeKey(), payload: {}, seq })
  for (const pubkey of survivors)
    await grant(relay, publisherSecret, pubkey, { scopeId: liveId, generation: next, scopeKey, scopeName })
  // `prev` records the moved scope's lineage (old d) for the Grant Index
  // `issued` entry: two devices that both rotate AND both move never
  // collide at one address, so the fork is detected in the index by its
  // shared prev — see mergeGrantIndex.
  return { scopeKey, generation: next, seq: pub.seq, scopeId: liveId,
           ...(newScopeId ? { prev: scopeId } : {}) }
}

/**
 * Delete a scope. On NIP-01 relays, replacement is destruction: the
 * tombstone (empty payload, fresh key granted to no one, bumped generation)
 * removes the previous ciphertext from every conforming relay. The NIP-09
 * kind-5 then asks relays to drop the tombstone too (advisory). Grantees see
 * generation supersession — indistinguishable from revocation, deliberately.
 */
export async function deleteScope(relay, publisherSecret, { scopeId, generation, seq }) {
  const signer = asSigner(publisherSecret)
  await publishScope(relay, signer, {
    scopeId, generation: generation + 1, scopeKey: newScopeKey(), payload: {}, seq,
  })
  const event = await signer.signEvent({
    kind: 5,
    created_at: now(),
    tags: [
      ['a', `${KIND_DATA_SET}:${await signer.getPublicKey()}:${scopeId}`],
      ['k', String(KIND_DATA_SET)],
    ],
    content: '',
  })
  const receipt = await relay.publish(event)
  return { event, ...receipt }
}

/**
 * Metadata hardening, item 4 (SPEC "Metadata-hardening profile"): pad a
 * payload so its serialized JSON lands exactly on a `bucketBytes` boundary
 * before encryption. NIP-44's own padding is fine-grained enough that a
 * field-level edit can still hop size classes; equal-length plaintexts make
 * equal-length ciphertexts, so payloads padded to the same bucket share one
 * class (publishScope's appended `updated_at` adds a constant, preserving
 * the equality). The filler rides in the reserved top-level `pad` member,
 * which readers ignore like any other unrecognized member. Opt-in per
 * publish: publishScope(relay, sk, { ..., payload: padTo(payload, 1024) }).
 */
export function padTo(payload, bucketBytes) {
  const bytes = (s) => new TextEncoder().encode(s).length
  const bare = bytes(JSON.stringify({ ...payload, pad: '' }))
  return { ...payload, pad: '='.repeat(Math.ceil(bare / bucketBytes) * bucketBytes - bare) }
}

// ---------------------------------------------------------------- grantee

/**
 * Collect and unwrap grants addressed to this keyholder.
 *
 * Full scan by default — and grants share the kind-1059 inbox with NIP-17
 * DMs, whose inner kind is encrypted, so a relay cannot be asked for
 * "grants only". That indistinguishability is an intended NIP-59 property
 * (the grant graph is what this protocol protects); the cost it imposes
 * cannot be filtered away server-side, only bounded. Bounding is what the
 * inbox cursor does (SPEC "Discovering new grants"): pass { since, seenIds }
 * — `since` the highest wrap created_at already processed, `seenIds` the
 * wrap ids already processed — and the scan turns incremental. Two rules
 * keep it correct against fuzz() above:
 *
 *  - the 1059 query reaches WRAP_OVERLAP *behind* the checkpoint, because
 *    a wrap delivered after the last scan may be timestamped up to two
 *    days older than everything that scan saw — a naive since = checkpoint
 *    silently loses such grants;
 *  - consecutive scans therefore overlap, so wraps are deduplicated by id:
 *    anything in `seenIds` (grant or DM) is never trial-unwrapped again.
 *
 * The advanced cursor rides on the returned array as `result.cursor` =
 * { since, ids }, with `ids` pruned to the trailing WRAP_OVERLAP window so
 * it stays bounded. Persist it *together with* the grants it accounts for
 * — the Grant Index `inbox` member is the natural home — never ahead of
 * them: a cursor that outruns its cache hides grants. A wrap a relay
 * transiently omitted merely gets re-trial-unwrapped when it reappears;
 * unwrapping is idempotent, so dedup is a cost optimization, never a
 * correctness dependency.
 */
export async function receiveGrants(relay, granteeSecret, { since, seenIds } = {}) {
  const signer = asSigner(granteeSecret)
  const granteePub = await signer.getPublicKey()
  const filter = { kinds: [1059], '#p': [granteePub] }
  if (since != null) filter.since = Math.max(since - WRAP_OVERLAP, 0)
  const wraps = await relay.query(filter)
  const known = new Set(seenIds ?? [])
  const checkpoint = wraps.reduce((m, w) => Math.max(m, w.created_at), since ?? 0)
  const grants = []
  for (const wrap of wraps) {
    if (known.has(wrap.id)) continue // overlap dedup: processed on a prior scan
    let rumor
    try { rumor = await giftUnwrap(signer, wrap) } catch { continue }
    if (rumor.kind !== KIND_GRANT) continue
    const [, address, relayHint] = rumor.tags.find(t => t[0] === 'a')
    const [kind, publisher, scopeId] = address.split(':')
    const { scope_key, scope_name } = JSON.parse(rumor.content)
    grants.push({
      publisher, scopeId, scopeName: scope_name, relayHint,
      // Who actually issued this grant (the authenticated rumor author) —
      // distinct from `publisher` (the a-tag's data-set owner). They differ
      // when a grantee re-gifts a scope key it holds: a *re-wrapped* grant,
      // which SPEC "Grant authentication" says MUST NOT pass as first-party
      // and SHOULD be rejected by default. receiveGrants stays permissive —
      // every grant is returned, flagged — and the default-reject policy
      // lives in latestGrants/addressBook ({ allowRewrapped: true } opts in).
      author: rumor.pubkey,
      rewrapped: rumor.pubkey !== publisher,
      generation: Number(rumor.tags.find(t => t[0] === 'v')?.[1] ?? 0),
      scopeKey: unb64(scope_key),
      issuedAt: rumor.created_at,
    })
  }
  // Next scan's dedup set: every wrap seen inside the window that the next
  // overlapping query can return again — including non-grants, so a DM
  // trial-unwrapped once is never trial-unwrapped twice.
  grants.cursor = {
    since: checkpoint,
    ids: wraps.filter(w => w.created_at >= checkpoint - WRAP_OVERLAP).map(w => w.id),
  }
  return grants
}

/**
 * Keep only the newest grant per (publisher, scope) — key rotations supersede.
 * Re-wrapped grants (author ≠ a-tag publisher, per SPEC "Grant authentication")
 * are rejected by default; { allowRewrapped: true } is the explicit-policy
 * escape hatch, and even then the record keeps `author`/`rewrapped` so callers
 * surface the distinct author. Honest-client enforcement only: a malicious
 * grantee can always hand the raw key to anyone out of band.
 */
export function latestGrants(grants, { allowRewrapped = false } = {}) {
  const best = new Map()
  for (const g of grants) {
    if (g.rewrapped && !allowRewrapped) continue
    const k = `${g.publisher}:${g.scopeId}`
    const cur = best.get(k)
    // Higher generation supersedes. EQUAL generations are legitimate after a
    // P3 collision repair — the reconciling re-grant carries the same `v` as
    // the losing grant it supersedes — so among equals the latest issued
    // wins (the rumor's created_at is honest publisher time; only seal and
    // wrap timestamps are fuzzed). Grant Index cache entries carry no
    // issuedAt (0) and so yield to any later first-party re-grant at the
    // same generation, which is exactly the reconcile case; re-wraps never
    // reach this comparison (dropped above).
    if (!cur || g.generation > cur.generation
        || (g.generation === cur.generation && (g.issuedAt ?? 0) > (cur.issuedAt ?? 0)))
      best.set(k, g)
  }
  return [...best.values()]
}

/**
 * Dereference a grant: fetch the current Scoped Data Set and decrypt it.
 * This is what makes the address book *live* — the grantee always reads the
 * publisher's authoritative current event, never a snapshot.
 * Returns { status: 'ok', data } or { status: 'stale' } if the scope key has
 * been rotated past this grant (i.e. access to future updates was revoked).
 * Both carry `generation`/`seq` — the event's (v, u) — for the caller to
 * persist as its high-water mark.
 *
 * `highWater` is that persisted per-scope `{ v, u }` mark (SPEC "Freshness
 * and rollback detection"): when the best event this fetch can see sits
 * lexicographically below it, the relay set is serving a rolled-back copy —
 * { status: 'rollback' } is returned instead of trusting what decrypts.
 * That makes rollback detectable, not impossible: a relay can still
 * withhold, and without a mark (or a relay carrying the newer event) there
 * is no signal.
 */
export async function fetchScope(relay, grantRecord, { highWater } = {}) {
  const [event] = await relay.query({
    kinds: [KIND_DATA_SET], authors: [grantRecord.publisher], '#d': [grantRecord.scopeId],
  })
  if (!event) return { status: 'missing' }
  const generation = Number(event.tags.find(t => t[0] === 'v')?.[1] ?? 0)
  const uTag = event.tags.find(t => t[0] === 'u')?.[1]
  const seq = uTag == null ? undefined : Number(uTag) // absent = pre-`u` event
  // (v, u) lexicographically below the stored mark → rollback. An absent `u`
  // compares as 0, so a pre-`u` copy served after a sequenced one is flagged.
  if (highWater && (generation < highWater.v
      || (generation === highWater.v && (seq ?? 0) < (highWater.u ?? 0))))
    return { status: 'rollback', generation, seq }
  if (generation > grantRecord.generation) return { status: 'stale', generation, seq }
  try {
    return { status: 'ok', generation, seq, data: symDecrypt(event.content, grantRecord.scopeKey) }
  } catch {
    return { status: 'stale', generation, seq } // MAC failure — wrong (rotated) key
  }
}

/**
 * Metadata hardening, item 2 (SPEC "Metadata-hardening profile"): decouple
 * an action from the event that prompted it. Waits a uniform random
 * 0..maxMs, then runs `fn` — e.g. jitterFetch(() => fetchScope(relay, g),
 * 90_000) after a grant arrives, so a relay seeing both the wrap delivery
 * and the first fetch of the granted address cannot line the two up on the
 * clock. Widens the correlation window; does not close it (SPEC Security 4).
 */
export async function jitterFetch(fn, maxMs) {
  await new Promise(r => setTimeout(r, Math.random() * maxMs))
  return fn()
}

/**
 * A grantee's whole address book: unwrap grants, keep the newest per scope,
 * dereference each. This IS the client. Options pass through to
 * latestGrants: re-wrapped grants are dropped unless { allowRewrapped: true }.
 *
 * With { index } (a loaded Grant Index) the book warm-starts per SPEC
 * "Discovering new grants": the `received` entries are the cache — the book
 * is rebuilt without unwrapping a single wrap — and the wrap scan turns
 * incremental from the index's `inbox` cursor ({ since, seenIds } override
 * it when passed explicitly). Cache entries are listed first, so a fresh
 * discovery supersedes a cached scope only by higher generation, and —
 * carrying no author — they pass latestGrants' re-wrap gate: accepting them
 * was the user's earlier, deliberate decision. Absent any index/cursor the
 * behavior is the historical full scan. The advanced cursor rides on the
 * result as `book.cursor`; persist it back alongside the entries it covers
 * (one Grant Index write updates cache + cursor atomically).
 */
export async function addressBook(relay, granteeSecret, { index, since, seenIds, ...opts } = {}) {
  // Tombstoned entries (deleted: true, P3 merge rule) stay in the index so
  // a merge cannot resurrect them, but are never dereferenced.
  const cached = index ? index.received.filter(e => !e.deleted).map(fromReceivedEntry) : []
  const fresh = await receiveGrants(relay, granteeSecret,
    { since: since ?? index?.inbox?.since, seenIds: seenIds ?? index?.inbox?.ids })
  const grants = latestGrants([...cached, ...fresh], opts)
  const book = await Promise.all(grants.map(async g => ({ ...g, ...await fetchScope(relay, g) })))
  book.cursor = fresh.cursor
  return book
}

// ---------------------------------------------------------- grant index

// NIP-44 to self: conversation key derived from one's own keypair, as in
// NIP-51 private items. The index carries all key material and must never
// exist unencrypted on a relay.

/**
 * Load the user's Grant Index. `issued` is the publisher's authoritative
 * record (everything a rotation needs); `received` is the grantee's private
 * address book — both recoverable from the nsec alone. The optional `inbox`
 * member is the grantee's persisted inbox cursor (see receiveGrants):
 * store `book.cursor` there in the same write that stores the entries it
 * covers, and addressBook({ index }) warm-starts from both. An index
 * without it (older writers) simply falls back to a full wrap scan.
 */
export async function loadGrantIndex(relay, secret) {
  const signer = asSigner(secret)
  const pub = await signer.getPublicKey()
  const [event] = await relay.query({ kinds: [KIND_GRANT_INDEX], authors: [pub] })
  return event
    ? JSON.parse(await signer.nip44Decrypt(pub, event.content))
    : { issued: [], received: [] }
}

/**
 * Encrypt and (re)publish the Grant Index. The EVENT is replaceable —
 * newest wins — but the CONTENT is merged, never blindly overwritten
 * (SPEC "Index merge rule"): load the currently published index, merge the
 * local state into it, publish the merge. Two devices editing concurrently
 * therefore both keep their edits; pre-P3 the loser's entries vanished.
 */
export async function saveGrantIndex(relay, secret, index) {
  const signer = asSigner(secret)
  const merged = mergeGrantIndex(await loadGrantIndex(relay, signer), index)
  const event = await signer.signEvent({
    kind: KIND_GRANT_INDEX,
    created_at: now(),
    tags: [],
    content: await signer.nip44Encrypt(await signer.getPublicKey(), JSON.stringify(merged)),
  })
  const receipt = await relay.publish(event)
  return { event, ...receipt }
}

/**
 * Merge two Grant Index versions (SPEC "Index merge rule"). `issued`
 * entries are keyed by `scope`, `received` by `a`; per key the survivor is
 * the entry with the greater `mtime` (absent compares as 0, so undated
 * pre-P3 entries always lose to dated ones), ties broken by the greater
 * `v`, then the lexicographically greater `key`; an entry and its tombstone
 * tied on all three resolve to the tombstone. Deletions are tombstones
 * ({ deleted: true, mtime }) precisely so this union cannot resurrect them.
 *
 * Two issued rivals that agree on `v` have their grantee lists unioned:
 * with the same key that is plain bookkeeping (both lists already hold the
 * current key); with DIFFERENT keys it is a same-v rotation collision — the
 * survivor is marked `conflicted: true` so reconcile() re-grants the
 * authoritative key to every survivor either device granted. Two live
 * moved entries sharing (prev, v) are a double-move fork (both devices
 * rotated AND moved, to different d's — no relay-level collision exists):
 * the same per-entry rule picks the one live identity; the dead branch
 * becomes a tombstone and its address is queued on the winner (`strand`)
 * for reconcile() to strand on-relay. The inbox cursor merges by
 * max(since) + id union. Output is key-sorted: merging is commutative,
 * byte-for-byte, so every device computes the identical index.
 */
export function mergeGrantIndex(a, b) {
  const wins = (x, y) =>
    (x.mtime ?? 0) !== (y.mtime ?? 0) ? (x.mtime ?? 0) > (y.mtime ?? 0)
    : (x.v ?? 0) !== (y.v ?? 0) ? (x.v ?? 0) > (y.v ?? 0)
    : (x.key ?? '') !== (y.key ?? '') ? (x.key ?? '') > (y.key ?? '')
    : !!x.deleted && !y.deleted
  const union = (xs, ys) => [...new Set([...(xs ?? []), ...(ys ?? [])])]
  const mergeList = (xs, ys, keyOf, annotate) => {
    const best = new Map()
    for (const e of [...(xs ?? []), ...(ys ?? [])]) {
      const k = keyOf(e), cur = best.get(k)
      if (!cur) { best.set(k, { ...e }); continue }
      const [w, l] = wins(e, cur) ? [{ ...e }, cur] : [cur, e]
      best.set(k, annotate ? annotate(w, l) : w)
    }
    return [...best.values()].sort((x, y) => keyOf(x) < keyOf(y) ? -1 : 1)
  }
  // Same-scope rivals: at equal v, union grantees; different keys = collision.
  const collide = (w, l) => {
    if (!w.deleted && !l.deleted && w.v === l.v) {
      w.grantees = union(w.grantees, l.grantees)
      if (w.key !== l.key) w.conflicted = true
    }
    return w
  }
  let issued = mergeList(a.issued, b.issued, e => e.scope, collide)
  // Double-move forks: group live moved entries by (prev, v).
  const forks = new Map()
  for (const e of issued)
    if (!e.deleted && e.prev != null)
      forks.set(`${e.prev}:${e.v}`, [...(forks.get(`${e.prev}:${e.v}`) ?? []), e])
  for (const rivals of forks.values()) {
    if (rivals.length < 2) continue
    const winner = rivals.reduce((w, e) => wins(e, w) ? e : w)
    winner.conflicted = true
    for (const loser of rivals) {
      if (loser === winner) continue
      winner.grantees = union(winner.grantees, loser.grantees)
      winner.strand = union(winner.strand, [loser.scope])
      // The dead branch's tombstone keeps its (v, key, mtime) so it also
      // beats the still-live copy a lagging device may merge in later.
      issued = issued.map(e => e === loser
        ? { scope: e.scope, v: e.v, key: e.key, mtime: e.mtime, deleted: true } : e)
    }
  }
  const received = mergeList(a.received, b.received, e => e.a)
  const cursors = [a.inbox, b.inbox].filter(Boolean)
  const inbox = cursors.length ? {
    since: Math.max(...cursors.map(c => c.since ?? 0)),
    ids: [...new Set(cursors.flatMap(c => c.ids ?? []))].sort(),
  } : undefined
  return { issued, received, ...(inbox ? { inbox } : {}) }
}

/**
 * Mandatory survivor reconciliation (SPEC "Concurrent publisher devices"):
 * run after an index sync. For every live issued entry, fetch the
 * authoritative surviving 30440 and compare:
 *
 *  - entry (v, key) matches the survivor and the merge flagged a collision
 *    (`conflicted`) → this device holds the authoritative key: re-grant it
 *    to every grantee (the union the merge built), clear the flag, restamp
 *    mtime. The re-grant carries the same v with a later issuedAt, which is
 *    what latestGrants prefers — survivors stranded on the losing key
 *    converge with no action of their own.
 *  - same v but the entry's key fails the MAC → this device LOST the
 *    collision. It cannot mint the winner's key, so it marks the entry
 *    conflicted: the flag rides the index to the winning device, whose own
 *    merge + reconcile completes the repair.
 *  - event v ahead of the entry → ordinary supersession by another device's
 *    later rotation; its entry arrives with the next merge. Behind → the
 *    relay set has not caught up with our own publish. Neither is repaired
 *    from here.
 *
 * A `strand` queue (dead double-move branches) is flushed first: each dead
 * address gets an on-relay tombstone (empty payload, throwaway key, bumped
 * generation) so its holders read supersession, exactly like a d-move's old
 * address. Returns the updated index — persist it with saveGrantIndex.
 */
export async function reconcile(relay, publisherSecret, index) {
  const signer = asSigner(publisherSecret)
  const pub = await signer.getPublicKey()
  const issued = []
  for (const entry of index.issued ?? []) {
    if (entry.deleted) { issued.push(entry); continue }
    const e = { ...entry }
    for (const dead of e.strand ?? [])
      await publishScope(relay, signer,
        { scopeId: dead, generation: e.v + 1, scopeKey: newScopeKey(), payload: {} })
    delete e.strand
    const [event] = await relay.query({ kinds: [KIND_DATA_SET], authors: [pub], '#d': [e.scope] })
    if (event) {
      const eventV = Number(event.tags.find(t => t[0] === 'v')?.[1] ?? 0)
      let holdsKey = false
      try { symDecrypt(event.content, unb64(e.key)); holdsKey = true } catch {}
      if (eventV === e.v && holdsKey && e.conflicted) {
        for (const grantee of e.grantees ?? [])
          await grant(relay, signer, grantee,
            { scopeId: e.scope, generation: e.v, scopeKey: unb64(e.key), scopeName: e.scope_name })
        delete e.conflicted
        e.mtime = mtimeNow()
      } else if (eventV === e.v && !holdsKey) {
        e.conflicted = true
      }
    }
    issued.push(e)
  }
  return { ...index, issued }
}

// Index entries use the spec's wire field names; these adapters convert to
// and from the in-memory grant/scope records the rest of the lib speaks.
// The optional content sequence rides as `u` (in-memory: `seq`): in `issued`
// it is the publisher's last-emitted `u` for the scope (bump from it with
// nextSeq); in `received` it is the grantee's persisted high-water. When the
// record has no seq (e.g. built from a grant, which carries no `u`), JSON
// serialization drops the field — absent means unknown, accept newest.
//
// `mtime` (SPEC "Index merge rule") is the entry's last local MODIFICATION
// time, the merge's primary comparator. A record fresh from a grant is a
// modification and stamps now; a record round-tripped through the index
// keeps its stored mtime, so merely re-saving never artificially freshens
// an entry past a rival device's genuinely newer edit. Callers making a
// deliberate edit (petname, grantee change) pass mtime explicitly or drop
// the field to restamp. `prev` is a moved scope's lineage — see rotateScope.

/** Wall-clock unix seconds for index-entry mtimes (event timestamps use the
 *  monotonic now() below; mtimes are merge metadata, not event fields). */
const mtimeNow = () => Math.floor(Date.now() / 1000)

export const toReceivedEntry = (g, petname, relays = []) => ({
  a: `${KIND_DATA_SET}:${g.publisher}:${g.scopeId}`, v: g.generation, u: g.seq,
  key: b64(g.scopeKey), petname, relays, mtime: g.mtime ?? mtimeNow(),
})
export const fromReceivedEntry = (e) => {
  const [, publisher, scopeId] = e.a.split(':')
  return { publisher, scopeId, generation: e.v, seq: e.u, scopeKey: unb64(e.key),
           petname: e.petname, mtime: e.mtime }
}
export const toIssuedEntry = ({ scopeId, scopeName, generation, scopeKey, seq, mtime, prev }, grantees) => ({
  scope: scopeId, scope_name: scopeName, v: generation, u: seq, key: b64(scopeKey), grantees,
  mtime: mtime ?? mtimeNow(), prev,
})
export const fromIssuedEntry = (e) => ({
  scopeId: e.scope, scopeName: e.scope_name, generation: e.v, seq: e.u,
  scopeKey: unb64(e.key), grantees: e.grantees, mtime: e.mtime, prev: e.prev,
})

// Monotonic: two publishes of the same replaceable/addressable event within
// one second would otherwise tie on created_at and lose NIP-01 replacement
// ("replaced: have newer event"). Strictly increasing timestamps fix the
// class; the ≤1s future drift under rapid publishing is harmless.
let lastTs = 0
const now = () => (lastTs = Math.max(Math.floor(Date.now() / 1000), lastTs + 1))
