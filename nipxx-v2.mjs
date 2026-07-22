// nipxx-v2.mjs — EXPERIMENTAL v2 track: Attenuable Scoped Data Grants.
// Reference implementation of SPEC-v2.md. Parallel to — and deliberately
// NOT entangled with — the v1 lib (nipxx.mjs): a new kind, a new file, and
// nothing imported across, so the v1 wire format cannot drift by accident
// (SPEC-PROPOSALS.md §P5; epic working rule 5). The NIP-59 helpers below are
// therefore small, intentional duplicates of their v1 twins.
//
// Event kinds (placeholders pending assignment):
//   31440  Attenuable Scoped Data Set  (addressable; per-field ciphertexts
//                                       under HKDF-derived subkeys of a root key)
//     442  Attenuable Data Grant       (unsigned rumor, NIP-59 gift wrap; a
//                                       NEW kind — see "why 442" below)
//
// The construction (SPEC-v2.md "The key tree"): a scope has a random 32-byte
// root key K. Everything else is derived by HKDF-Expand over SHA-256 — the
// primitive NIP-44 already uses for its per-message keys, so no new
// cryptography enters the stack:
//
//   K_f(g)  = HKDF-Expand(K, "nipda/v2/field:" || f || ":" || g, 32)   field key
//   K_m     = HKDF-Expand(K, "nipda/v2/manifest",               32)   manifest key
//   label_f = hex(HKDF-Expand(K, "nipda/v2/label:" || f,         8))   wire label
//
// A grant conveys either K itself (full grant — every subkey derives) or an
// arbitrary SUBSET of field subkeys plus K_m (attenuated grant). HKDF-Expand
// is one-way and per-info independent, so a subkey holder can reach neither K
// nor any sibling subkey: an attenuated grantee cryptographically CANNOT read
// fields it was not granted — the attenuation half of DESIGN-REVIEW
// weaknesses 1/2. Rotating one field (bump its generation g) strands only
// that field's attenuated holders — per-field revocation, O(that field's
// holders), which is what shrinks weakness 3's rotation burst.
//
// Honest limits, stated up front exactly as the v1 spec states its own
// (SPEC-v2.md "Security"): every key here is still a bearer token. A holder
// can re-share whatever it holds out of band — attenuation bounds what a
// grantee can DECRYPT, never what a malicious holder can re-share of what it
// legitimately holds. There is no cryptographic re-delegation control (an
// onward re-wrap can only NARROW, but it cannot be prevented), and
// expiration remains advisory, enforced by honest clients only.
//
// Why the grant rumor is kind 442, not 440: v1 readers gate the 1059 inbox
// scan on rumor.kind !== 440 BEFORE parsing content; a kind-440 rumor whose
// content lacks scope_key crashes an unmodified v1 receiveGrants (unb64 of a
// missing member throws, uncaught, aborting the whole scan — verified against
// nipxx.mjs). Versioning by rumor kind makes v1's skip structural: 442 wraps
// share the same 1059 inbox (indistinguishable to relays, as intended) and
// v1 readers pass over them without ever touching the payload.
//
// Every flow takes a `relay`: any object with publish(event) and query(filter),
// same contract as the v1 lib — relay.mjs and liverelay.mjs drive both.

import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, nip44, verifyEvent } from 'nostr-tools'
import { expand as hkdfExpand } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

export const KIND_DATA_SET_V2 = 31440
export const KIND_GRANT_V2 = 442

// ------------------------------------------------------------- key tree

const utf8 = (s) => new TextEncoder().encode(s)
const hex = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')

/** The scope's root key: a random 32-byte symmetric key, exactly like a v1
 *  scope key. A CSPRNG output is a valid HKDF PRK (the same argument by
 *  which v1 feeds a raw scope key to NIP-44, whose per-message keys are
 *  themselves HKDF-Expand of it). */
export const newRootKey = () => crypto.getRandomValues(new Uint8Array(32))

// Field names MUST match /^[a-z0-9_-]+$/ (SPEC-v2 "The key tree") — the
// vCard-lowercase convention v1 already follows, and it keeps every HKDF
// info string unambiguous: ":" cannot occur inside a name, so
// "field:email:2" parses one way only.
const checkField = (f) => {
  if (typeof f !== 'string' || !/^[a-z0-9_-]+$/.test(f)) throw new Error(`invalid field name: ${f}`)
  return f
}

/** Field subkey for field `f` at per-field generation `g`. One-way from K;
 *  independent per (f, g): holding any set of subkeys reveals neither K nor
 *  any subkey outside the set. The generation is part of the derivation —
 *  that is what makes per-field ROTATION possible at all: bump g and the
 *  field has a fresh key no holder of the old one can compute. */
export const deriveFieldKey = (rootKey, field, generation = 1) =>
  hkdfExpand(sha256, rootKey, utf8(`nipda/v2/field:${checkField(field)}:${generation}`), 32)

/** Manifest key: held by EVERY grantee (full grants derive it; attenuated
 *  grants carry it), rotates only with the root. The manifest is the
 *  cleartext-to-holder map of field names — cleartext to holders, ciphertext
 *  to relays: field names never appear on the wire. */
export const deriveManifestKey = (rootKey) =>
  hkdfExpand(sha256, rootKey, utf8('nipda/v2/manifest'), 32)

/** Wire label for a field: the opaque name under which the field's
 *  ciphertext and `vf` tag travel. Derived, so the publisher needs no label
 *  state — and because it derives from K, every label changes when the root
 *  rotates, severing a relay's longitudinal per-field trail at each root
 *  rotation (the same move P6 makes with the `d` tag). Labels are public;
 *  HKDF's PRF security means they reveal nothing about K or the subkeys. */
export const deriveLabel = (rootKey, field) =>
  hex(hkdfExpand(sha256, rootKey, utf8(`nipda/v2/label:${checkField(field)}`), 8))

const b64 = (bytes) => btoa(String.fromCharCode(...bytes))
const unb64 = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0))

// NIP-44 v2 payload format with a raw derived key as the conversation key —
// same construction, and the same argument for it, as v1's symEncrypt.
const symEncrypt = (obj, key) => nip44.v2.encrypt(JSON.stringify(obj), key)
const symDecrypt = (ciphertext, key) => JSON.parse(nip44.v2.decrypt(ciphertext, key))

// ------------------------------------------------------------------ signers
//
// Same signer contract as the v1 lib: a raw 32-byte secret key or an object
// { getPublicKey, signEvent, nip44Encrypt, nip44Decrypt } (NIP-07 shaped).

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

// NIP-59, duplicated from the v1 lib (isolation over reuse — see header).
// Timestamps fuzzed up to two days into the past, per the NIP.

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

// ---------------------------------------------------------------- publisher

/** Next content sequence after `prev` — v1's `u` discipline, unchanged. */
export const nextSeq = (prev) => (Number(prev) || 0) + 1

// Per-process last-emitted `u` per (publisher, scope), as in the v1 lib.
const seqs = new Map()

/**
 * Publish (or replace) an Attenuable Scoped Data Set (kind 31440).
 *
 * `fields` is { name: value } (any JSON values); each is encrypted
 * independently under K_f(g) with g from `fieldGenerations` (default 1).
 * The wire content is { m, f }: `m` the manifest ciphertext under K_m —
 * { name, updated_at, fields: { <name>: { label, v } } } — and `f` the
 * per-LABEL ciphertext map. Tags carry v1's counters with v1's exact
 * semantics — `v` the ROOT rotation generation, `u` the per-scope content
 * sequence — plus one `["vf", <label>, <g>]` per field: per-field rotation
 * generations, relay-visible under opaque labels so a holder can spot a
 * single field's rotation without a fetch-and-decrypt, at the disclosed
 * metadata price that a relay sees per-label rotation counters too
 * (SPEC-v2 "What a relay sees").
 *
 * Returns { event, seq, ...receipt } exactly as v1's publishScope does.
 */
export async function publishAttenuableScope(relay, publisherSecret,
    { scopeId, rootGeneration = 1, rootKey, name, fields, fieldGenerations = {}, seq }) {
  const ts = now()
  const signer = asSigner(publisherSecret)
  const scopeRef = `${await signer.getPublicKey()}:${scopeId}`
  if (seq == null) seq = nextSeq(seqs.get(scopeRef))
  seqs.set(scopeRef, seq)
  const manifest = { name, updated_at: ts, fields: {} }
  const wire = {}
  const vfTags = []
  for (const field of Object.keys(fields).sort()) {   // sorted: deterministic layout
    const g = fieldGenerations[field] ?? 1
    const label = deriveLabel(rootKey, field)
    manifest.fields[field] = { label, v: g }
    wire[label] = symEncrypt(fields[field], deriveFieldKey(rootKey, field, g))
    vfTags.push(['vf', label, String(g)])
  }
  const event = await signer.signEvent({
    kind: KIND_DATA_SET_V2,
    created_at: ts,
    tags: [['d', scopeId], ['v', String(rootGeneration)], ['u', String(seq)], ...vfTags],
    content: JSON.stringify({ m: symEncrypt(manifest, deriveManifestKey(rootKey)), f: wire }),
  })
  const receipt = await relay.publish(event)
  return { event, seq, ...receipt }
}

/**
 * Issue an Attenuable Data Grant (kind 442 rumor, NIP-59 gift-wrapped).
 *
 * Two shapes, one function:
 *   full grant        — pass `rootKey`: content carries root_key alone; the
 *                       grantee derives K_m, every label, and every K_f(g)
 *                       — including generations that do not exist yet, so
 *                       root holders ride through per-field rotations with
 *                       NO re-grant.
 *   attenuated grant  — pass `manifestKey` + `subkeys` ({ field: { v, key } }):
 *                       the grantee can decrypt the manifest and exactly
 *                       those (field, generation) pairs, and nothing else —
 *                       not by policy but because no other key is derivable
 *                       from what it holds.
 *
 * `publisher` defaults to the granter (the first-party case). A holder
 * re-wrapping onward passes the original publisher — the a-tag keeps naming
 * the real scope owner, and the seal author (the granter) then differs from
 * it, which is precisely what marks the grant `rewrapped` for receivers
 * (v1's "Grant authentication" rule, carried over verbatim in SPEC-v2).
 */
export async function grantFields(relay, granterSecret, granteePubkey,
    { publisher, scopeId, rootGeneration, rootKey, manifestKey, subkeys, scopeName, relayHint = '' }) {
  const signer = asSigner(granterSecret)
  const granterPub = await signer.getPublicKey()
  publisher = publisher ?? granterPub
  const content = rootKey
    ? { scope_name: scopeName, root_key: b64(rootKey) }
    : { scope_name: scopeName, manifest_key: b64(manifestKey),
        subkeys: Object.fromEntries(Object.entries(subkeys)
          .map(([f, s]) => [checkField(f), { v: s.v, key: b64(s.key) }])) }
  const rumor = {
    pubkey: granterPub,
    kind: KIND_GRANT_V2,
    created_at: now(),
    tags: [
      ['a', `${KIND_DATA_SET_V2}:${publisher}:${scopeId}`, relayHint],
      ['v', String(rootGeneration)],
    ],
    content: JSON.stringify(content),
  }
  const wrap = await giftWrap(signer, granteePubkey, rumor)
  const receipt = await relay.publish(wrap)
  return { wrap, ...receipt }
}

/**
 * Narrow a held capability to `fieldNames` — the onward-attenuation
 * primitive. From a full capability it mints the subset's subkeys (pass
 * `fieldGenerations` — current generations, as returned by
 * fetchAttenuableScope — so the minted keys match the live event); from an
 * attenuated capability it filters the held subkeys. Asking for a field the
 * capability does not hold throws: widening is impossible not because this
 * function refuses (it does), but because no key material for the field
 * exists to hand over — the throw is the API surfacing the cryptographic
 * fact. Feed the result to grantFields (with `publisher` set) to re-wrap
 * onward; receivers will see it `rewrapped`, exactly like a v1 re-wrap,
 * with one honest difference: the blast radius of what a re-wrapping holder
 * CAN pass along is now bounded by what it holds.
 */
export function attenuate(cap, fieldNames, { fieldGenerations = {} } = {}) {
  const subkeys = {}
  for (const f of fieldNames) {
    checkField(f)
    if (cap.rootKey) {
      const g = fieldGenerations[f] ?? 1
      subkeys[f] = { v: g, key: deriveFieldKey(cap.rootKey, f, g) }
    } else {
      const held = cap.subkeys?.[f]
      if (!held) throw new Error(`cannot widen: no subkey held for field "${f}"`)
      subkeys[f] = { v: held.v, key: held.key }
    }
  }
  return {
    publisher: cap.publisher, scopeId: cap.scopeId, rootGeneration: cap.rootGeneration,
    manifestKey: cap.manifestKey ?? deriveManifestKey(cap.rootKey),
    subkeys, scopeName: cap.scopeName,
  }
}

/**
 * Rotate ONE field: bump its generation, republish (all ciphertexts are
 * fresh either way — NIP-44 nonces — but only this field's KEY changes),
 * and re-grant the new subkey to `survivors`: the ATTENUATED holders of
 * this field who keep access. Root holders need nothing — they derive
 * K_f(g+1) the moment the manifest shows g+1 — and attenuated holders of
 * OTHER fields are untouched. The revoked field-holder's old subkey now
 * fails the MAC on the field's fresh ciphertext: cut off from this field's
 * future updates, keeping (unavoidably, as everywhere in this protocol)
 * whatever plaintext it already decrypted. Cost: O(this field's attenuated
 * holders) — the per-field answer to weakness 3's O(scope grantees) burst.
 *
 * `fields` is the full current payload (a publish replaces the whole
 * addressable event); `fieldGenerations` the current generations. Returns
 * the bumped map, the new subkey, and the publish sequence.
 */
export async function rotateField(relay, publisherSecret,
    { scopeId, rootGeneration, rootKey, name, fields, fieldGenerations = {}, field, survivors = [], scopeName, seq }) {
  const generation = (fieldGenerations[checkField(field)] ?? 1) + 1
  const bumped = { ...fieldGenerations, [field]: generation }
  const pub = await publishAttenuableScope(relay, publisherSecret,
    { scopeId, rootGeneration, rootKey, name, fields, fieldGenerations: bumped, seq })
  const subkey = { v: generation, key: deriveFieldKey(rootKey, field, generation) }
  for (const pubkey of survivors)
    await grantFields(relay, publisherSecret, pubkey, {
      scopeId, rootGeneration, manifestKey: deriveManifestKey(rootKey),
      subkeys: { [field]: subkey }, scopeName,
    })
  return { fieldGenerations: bumped, seq: pub.seq, subkey }
}

/**
 * Rotate the ROOT: a fresh random K, the v1 revocation semantics at scope
 * level. This is what expels a FULL-grant holder (or a field-revoked
 * holder's residual manifest access — see SPEC-v2 "Security"): everything
 * re-keys, because everything derives from K — manifest key, every field
 * key, every label (so the relay-visible per-field trail breaks too, the
 * same severance P6 buys by moving `d`). Per-field generations restart at 1
 * under the new root: v_f is scoped to its root generation.
 *
 * The new `v` follows v1's Lamport rule — max(local, relay-observed) + 1 —
 * so the counter discipline matches v1 exactly. `survivors` is
 * [{ pubkey, fields? }]: entries with `fields` are re-granted attenuated,
 * the rest get the new root. Cost: O(all survivors), unavoidable — the
 * revoked party held (or could reach) everything.
 */
export async function rotateRoot(relay, publisherSecret,
    { scopeId, rootGeneration, name, fields, survivors = [], scopeName, seq }) {
  const signer = asSigner(publisherSecret)
  const publisherPub = await signer.getPublicKey()
  const rootKey = newRootKey()
  const [cur] = await relay.query({
    kinds: [KIND_DATA_SET_V2], authors: [publisherPub], '#d': [scopeId],
  })
  const seenV = Number(cur?.tags.find(t => t[0] === 'v')?.[1] ?? 0)
  const next = Math.max(rootGeneration, seenV) + 1
  const pub = await publishAttenuableScope(relay, publisherSecret,
    { scopeId, rootGeneration: next, rootKey, name, fields, seq })
  const cap = { publisher: publisherPub, scopeId, rootGeneration: next, rootKey, scopeName }
  for (const s of survivors)
    await grantFields(relay, publisherSecret, s.pubkey,
      s.fields ? attenuate(cap, s.fields) : cap)
  return { rootKey, rootGeneration: next, seq: pub.seq }
}

// ---------------------------------------------------------------- grantee

/**
 * Collect and unwrap v2 grants (kind 442 rumors) addressed to this
 * keyholder. The mirror of v1's receiveGrants — same 1059 inbox, same
 * incremental-cursor contract ({ since, seenIds } in, `result.cursor` out,
 * WRAP_OVERLAP reach-back and id dedup; see the v1 lib for the full
 * rationale) — gated on the v2 rumor kind, so the two readers pass over
 * each other's grants by construction. Records carry `author` and
 * `rewrapped` exactly as v1 does (SPEC-v2 carries the v1 "Grant
 * authentication" rule over unchanged).
 */
export async function receiveGrantsV2(relay, granteeSecret, { since, seenIds } = {}) {
  const signer = asSigner(granteeSecret)
  const granteePub = await signer.getPublicKey()
  const filter = { kinds: [1059], '#p': [granteePub] }
  if (since != null) filter.since = Math.max(since - WRAP_OVERLAP, 0)
  const wraps = await relay.query(filter)
  const known = new Set(seenIds ?? [])
  const checkpoint = wraps.reduce((m, w) => Math.max(m, w.created_at), since ?? 0)
  const grants = []
  for (const wrap of wraps) {
    if (known.has(wrap.id)) continue
    let rumor
    try { rumor = await giftUnwrap(signer, wrap) } catch { continue }
    if (rumor.kind !== KIND_GRANT_V2) continue
    const [, address, relayHint] = rumor.tags.find(t => t[0] === 'a')
    const [, publisher, scopeId] = address.split(':')
    const c = JSON.parse(rumor.content)
    grants.push({
      publisher, scopeId, scopeName: c.scope_name, relayHint,
      author: rumor.pubkey,
      rewrapped: rumor.pubkey !== publisher,
      rootGeneration: Number(rumor.tags.find(t => t[0] === 'v')?.[1] ?? 0),
      rootKey: c.root_key ? unb64(c.root_key) : undefined,
      manifestKey: c.manifest_key ? unb64(c.manifest_key)
        : c.root_key ? deriveManifestKey(unb64(c.root_key)) : undefined,
      subkeys: c.subkeys ? Object.fromEntries(Object.entries(c.subkeys)
        .map(([f, s]) => [f, { v: Number(s.v), key: unb64(s.key) }])) : undefined,
      issuedAt: rumor.created_at,
    })
  }
  grants.cursor = {
    since: checkpoint,
    ids: wraps.filter(w => w.created_at >= checkpoint - WRAP_OVERLAP).map(w => w.id),
  }
  return grants
}

/**
 * Reduce raw grants to one effective CAPABILITY per (publisher, scope,
 * author). Where v1's latestGrants picks a single newest grant, v2 must
 * MERGE: after a per-field rotation the survivor holds its original
 * attenuated grant PLUS a one-field re-grant, and its effective capability
 * is the union — per field, the highest per-field generation wins. The
 * rules, in order:
 *
 *  - re-wrapped grants (author ≠ a-tag publisher) are dropped by default,
 *    { allowRewrapped: true } opting in — v1's policy, unchanged. Keying by
 *    author additionally keeps re-wrapped capability separate from
 *    first-party capability even when allowed: key material from different
 *    issuers is never blended into one record.
 *  - a higher ROOT generation supersedes everything below it (those grants
 *    died with the old root).
 *  - within a root generation, a full grant (root_key) subsumes subkeys;
 *    otherwise subkeys union per-field with max v_f.
 */
export function latestGrantsV2(grants, { allowRewrapped = false } = {}) {
  const best = new Map()
  for (const g of grants) {
    if (g.rewrapped && !allowRewrapped) continue
    const k = `${g.publisher}:${g.scopeId}:${g.author}`
    const cur = best.get(k)
    if (!cur || g.rootGeneration > cur.rootGeneration) {
      best.set(k, { ...g, subkeys: g.subkeys ? { ...g.subkeys } : undefined })
      continue
    }
    if (g.rootGeneration < cur.rootGeneration) continue
    // Same root generation: merge into the effective capability.
    if (g.rootKey && !cur.rootKey) { cur.rootKey = g.rootKey; cur.subkeys = undefined }
    if (!cur.rootKey && g.subkeys) {
      cur.subkeys ??= {}
      for (const [f, s] of Object.entries(g.subkeys))
        if (!cur.subkeys[f] || s.v > cur.subkeys[f].v) cur.subkeys[f] = s
    }
    cur.manifestKey ??= g.manifestKey
    cur.issuedAt = Math.max(cur.issuedAt ?? 0, g.issuedAt ?? 0)
  }
  return [...best.values()]
}

/**
 * Dereference a capability: fetch the current kind-31440 event and decrypt
 * what the held keys reach. Returns
 *
 *   { status, generation, seq, name, updated_at, fields, fieldGenerations }
 *
 * with per-field entries { status: 'ok', v, value } | { status: 'stale', v }
 * (a subkey is held but the field rotated past it — or, transiently, the
 * relay serves an event older than the re-grant) | { status: 'locked', v }
 * (no subkey held: the field is cryptographically unreadable, which the
 * caller should surface as "not granted", never as "empty"). Top-level
 * status mirrors v1's vocabulary: 'ok' | 'missing' | 'stale' (root
 * generation superseded — or the manifest MAC fails, the same signal by
 * other means) | 'rollback' (the served (v, u) sits below the caller's
 * persisted `highWater` mark — v1's freshness rule, verbatim).
 */
export async function fetchAttenuableScope(relay, cap, { highWater } = {}) {
  const [event] = await relay.query({
    kinds: [KIND_DATA_SET_V2], authors: [cap.publisher], '#d': [cap.scopeId],
  })
  if (!event) return { status: 'missing' }
  const generation = Number(event.tags.find(t => t[0] === 'v')?.[1] ?? 0)
  const uTag = event.tags.find(t => t[0] === 'u')?.[1]
  const seq = uTag == null ? undefined : Number(uTag)
  if (highWater && (generation < highWater.v
      || (generation === highWater.v && (seq ?? 0) < (highWater.u ?? 0))))
    return { status: 'rollback', generation, seq }
  if (generation > cap.rootGeneration) return { status: 'stale', generation, seq }
  const { m, f: wire } = JSON.parse(event.content)
  const manifestKey = cap.manifestKey ?? deriveManifestKey(cap.rootKey)
  let manifest
  try { manifest = symDecrypt(m, manifestKey) } catch {
    return { status: 'stale', generation, seq }   // wrong root at same v — MAC is the signal
  }
  const fields = {}
  const fieldGenerations = {}
  for (const [name, meta] of Object.entries(manifest.fields ?? {})) {
    fieldGenerations[name] = meta.v
    const key = cap.rootKey ? deriveFieldKey(cap.rootKey, name, meta.v)
      : cap.subkeys?.[name]?.v === meta.v ? cap.subkeys[name].key
      : undefined
    if (!key) {
      fields[name] = { status: cap.subkeys?.[name] ? 'stale' : 'locked', v: meta.v }
      continue
    }
    try { fields[name] = { status: 'ok', v: meta.v, value: symDecrypt(wire[meta.label], key) } }
    catch { fields[name] = { status: 'stale', v: meta.v } }
  }
  return { status: 'ok', generation, seq, name: manifest.name,
           updated_at: manifest.updated_at, fields, fieldGenerations }
}

/**
 * A grantee's whole v2 book: unwrap 442 grants, reduce to effective
 * capabilities, dereference each. The v2 twin of v1's addressBook, minus
 * the Grant Index warm start — index integration is an open question the
 * experimental track deliberately leaves out (SPEC-v2 "Open questions").
 */
export async function attenuableBook(relay, granteeSecret, opts = {}) {
  const grants = await receiveGrantsV2(relay, granteeSecret, opts)
  const caps = latestGrantsV2(grants, opts)
  const book = await Promise.all(caps.map(async c => ({ ...c, ...await fetchAttenuableScope(relay, c) })))
  book.cursor = grants.cursor
  return book
}

// Monotonic per-process clock, as in the v1 lib: strictly increasing
// created_at so rapid replacements never tie under NIP-01.
let lastTs = 0
const now = () => (lastTs = Math.max(Math.floor(Date.now() / 1000), lastTs + 1))
