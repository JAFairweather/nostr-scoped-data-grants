// smoke-capability-fixtures.mjs — offline verifier for fixtures/capability-grants-v1.json (q-076).
//
//   node smoke-capability-fixtures.mjs
//
// Verifies cryptographic event hashes, BIP-340 Schnorr signatures, da-scope
// salted SHA-256 commitments (including the live relay vector), SPEC.md rumor
// vs bare capability wire-profile disambiguation, all 10 da-cap shapes,
// revocation semantics, and negative / cross-consumer divergence controls.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { getEventHash, verifyEvent } from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { schnorr } from '@noble/curves/secp256k1.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = resolve(HERE, 'fixtures/capability-grants-v1.json')
const rawJson = readFileSync(FIXTURE_PATH, 'utf8')
const bundle = JSON.parse(rawJson)

let passed = 0
let failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  if (ok) passed++
  else failed++
}

const EXPECTED_CAPS = [
  'admit',
  'admit+read',
  'task',
  'task+act',
  'task-relay',
  'shadow',
  'mirror',
  'mention',
  'onboard',
  'memory-write',
]

function strictDaScopeHash(subject, saltHex, domainLabel = 'waggle/da-scope/v1') {
  if (typeof saltHex !== 'string' || (!/^([0-9a-f]{2})+$/i.test(saltHex) && saltHex !== '')) {
    throw new Error(`Invalid saltHex: ${saltHex}`)
  }
  const saltBytes = saltHex === '' ? new Uint8Array(0) : hexToBytes(saltHex)
  const preimage = concatBytes(
    utf8ToBytes(domainLabel),
    new Uint8Array([0x00]),
    utf8ToBytes(subject),
    saltBytes,
  )
  return bytesToHex(sha256(preimage))
}

function relayPolicySaltValid(saltHex) {
  return typeof saltHex === 'string' && /^[0-9a-f]{32}$/.test(saltHex)
}

function nodeLooseDaScopeHash(subject, saltHex, domainLabel = 'waggle/da-scope/v1') {
  const saltBytes = Buffer.from(saltHex || '', 'hex')
  const preimage = Buffer.concat([
    Buffer.from(`${domainLabel}\0`, 'utf8'),
    Buffer.from(subject, 'utf8'),
    saltBytes,
  ])
  return bytesToHex(sha256(preimage))
}

function verifySignedNostrEvent(ev) {
  // Always parse a fresh plain object so nostr-tools [verifiedSymbol] cache cannot mask mutations
  const fresh = JSON.parse(JSON.stringify(ev))
  if (typeof fresh.id !== 'string' || !/^[0-9a-f]{64}$/.test(fresh.id)) return false
  if (typeof fresh.pubkey !== 'string' || !/^[0-9a-f]{64}$/.test(fresh.pubkey)) return false
  if (typeof fresh.sig !== 'string' || !/^[0-9a-f]{128}$/.test(fresh.sig)) return false
  const recomputedId = getEventHash(fresh)
  if (recomputedId !== fresh.id) return false
  const nobleValid = schnorr.verify(hexToBytes(fresh.sig), hexToBytes(fresh.id), hexToBytes(fresh.pubkey))
  const nostrToolsValid = verifyEvent(fresh)
  return nobleValid && nostrToolsValid
}

function tagValue(ev, name) {
  const t = ev.tags.find((row) => row[0] === name)
  return t ? t[1] : undefined
}

function classifyWireProfile(ev) {
  const aTag = tagValue(ev, 'a')
  if (typeof aTag === 'string' && aTag.startsWith('30440:') && ev.id === undefined && ev.sig === undefined) {
    return 'scoped_data_rumor'
  }
  if (
    (ev.kind === 440 && tagValue(ev, 'p') && tagValue(ev, 'da-scope') && tagValue(ev, 'da-cap') && !aTag) ||
    (ev.kind === 441 && tagValue(ev, 'e') && !aTag)
  ) {
    return 'capability_public_event'
  }
  return 'unknown'
}

function isExpiredStrictNip40(ev, nowSec) {
  const exp = tagValue(ev, 'expiration')
  if (exp === undefined) return false
  if (!/^\d+$/.test(exp)) return true // fail-closed on non-digit expiration
  return Number(exp) <= nowSec
}

function foldStrictSameAuthorOrderIndependent(grants, revocations, nowSec) {
  const grantsById = new Map(grants.map((g) => [g.id, g]))
  const revokedIds = new Set()
  for (const r of revocations) {
    if (r.kind !== 441 || !verifySignedNostrEvent(r)) continue
    const targetId = tagValue(r, 'e')
    const target = grantsById.get(targetId)
    if (target && r.pubkey === target.pubkey) {
      revokedIds.add(targetId)
    }
  }
  return grants.filter((g) => verifySignedNostrEvent(g) && !revokedIds.has(g.id) && !isExpiredStrictNip40(g, nowSec))
}

function foldGrantorPoolTimestampSorted(grants, revocations, grantorsSet, nowSec) {
  const all = [...grants, ...revocations].sort((a, b) => a.created_at - b.created_at)
  const live = new Map()
  for (const ev of all) {
    if (!verifySignedNostrEvent(ev) || !grantorsSet.has(ev.pubkey)) continue
    if (ev.kind === 441) {
      const targetId = tagValue(ev, 'e')
      if (targetId) live.delete(targetId)
    } else if (ev.kind === 440 && !isExpiredStrictNip40(ev, nowSec)) {
      live.set(ev.id, ev)
    }
  }
  return [...live.values()]
}

console.log('1. Bundle hygiene & live relay da-scope reference vector')
check('schema_version is capability-grants-fixtures/v1', bundle.schema_version === 'capability-grants-fixtures/v1')
check(
  'fixture JSON contains zero private keys or nsec strings',
  !rawJson.includes('nsec1') &&
    !/"(sk|privkey|secret_key|private_key)"\s*:/.test(rawJson),
)

const live = bundle.da_scope_spec.live_relay_reference_vector
const recomputedLive = strictDaScopeHash(live.subject, live.salt_hex, bundle.da_scope_spec.domain_label)
check(
  'live relay da-scope vector matches expected SHA-256 commitment',
  recomputedLive === live.expected_hash,
  `${recomputedLive.slice(0, 16)}…`,
)
check(
  'domain separation holds (changing label changes commitment)',
  strictDaScopeHash(live.subject, live.salt_hex, 'waggle/da-scope/v2') !== live.expected_hash,
)

console.log('\n2. Wire-profile disambiguation (SPEC.md rumors vs bare capability events)')
for (const rv of bundle.scoped_data_rumor_vectors) {
  const r = rv.rumor
  check(
    `${rv.id} is unsigned NIP-59 rumor with 30440 coordinate`,
    r.id === undefined &&
      r.sig === undefined &&
      classifyWireProfile(r) === 'scoped_data_rumor' &&
      !r.tags.some((t) => t[0] === 'da-cap' || t[0] === 'da-scope'),
  )
}

console.log('\n3. Signed kind:440 capability grant vectors (all 10 da-cap values)')
const seenCaps = new Set()
for (const gv of bundle.capability_grant_vectors) {
  const ev = gv.event
  seenCaps.add(gv.da_cap)
  const sigOk = verifySignedNostrEvent(ev)
  const scopeTag = ev.tags.find((t) => t[0] === 'da-scope')
  const recomputedScope = strictDaScopeHash(gv.subject_preimage, gv.salt_hex)
  const scopeOk =
    Array.isArray(scopeTag) &&
    scopeTag[1] === gv.expected_da_scope &&
    scopeTag[2] === gv.salt_hex &&
    recomputedScope === gv.expected_da_scope &&
    relayPolicySaltValid(gv.salt_hex)
  const expectedIssuerPk = bundle.identities[gv.issuer_role]?.pubkey
  const expectedGranteePk = bundle.identities[gv.grantee_role]?.pubkey
  const rolesOk = ev.pubkey === expectedIssuerPk && tagValue(ev, 'p') === expectedGranteePk
  const wireOk =
    ev.kind === 440 &&
    ev.content === '' &&
    tagValue(ev, 'da-cap') === gv.da_cap &&
    classifyWireProfile(ev) === 'capability_public_event' &&
    !isExpiredStrictNip40(ev, bundle.evaluation_now)

  let capSpecificOk = true
  if (gv.da_cap === 'shadow' || gv.da_cap === 'onboard') {
    capSpecificOk = tagValue(ev, 'p') !== ev.pubkey && gv.subject_preimage === ev.pubkey
  }
  if (gv.da_cap === 'onboard') {
    capSpecificOk =
      capSpecificOk &&
      typeof tagValue(ev, 'policy') === 'string' &&
      tagValue(ev, 'policy').length > 0 &&
      tagValue(ev, 'policy').length <= 128 &&
      tagValue(ev, 'age') === 'confirmed'
  }
  if (gv.da_cap === 'mention') {
    const handle = tagValue(ev, 'name')
    capSpecificOk =
      tagValue(ev, 'p') !== gv.subject_preimage &&
      typeof handle === 'string' &&
      /^[a-z0-9][a-z0-9._-]{0,31}$/i.test(handle)
  }
  if (gv.da_cap === 'mirror') {
    const tos = tagValue(ev, 'tos')
    capSpecificOk = typeof tos === 'string' && /^[0-9a-f]{64}$/.test(tos)
  }

  check(
    `${gv.id} (${gv.da_cap}) valid sig, da-scope, roles & tag invariants`,
    sigOk && scopeOk && rolesOk && wireOk && capSpecificOk,
    `id=${ev.id.slice(0, 12)}…`,
  )
}

check(
  'fixture corpus covers all 10 da-cap values in code',
  EXPECTED_CAPS.every((c) => seenCaps.has(c)) && seenCaps.size === EXPECTED_CAPS.length,
  `count=${seenCaps.size}`,
)

console.log('\n4. Signed kind:441 revocation vectors & consumer fold behavior')
const grantMap = new Map(bundle.capability_grant_vectors.map((v) => [v.id, v.event]))
const revMap = new Map(bundle.capability_revocation_vectors.map((v) => [v.id, v.event]))
for (const rev of bundle.capability_revocation_vectors) {
  const ev = rev.event
  const target = grantMap.get(rev.revokes_vector_id)
  check(
    `${rev.id} valid BIP-340 sig & points to ${rev.revokes_vector_id}`,
    ev.kind === 441 &&
      ev.content === '' &&
      verifySignedNostrEvent(ev) &&
      classifyWireProfile(ev) === 'capability_public_event' &&
      Boolean(target) &&
      tagValue(ev, 'e') === target.id &&
      rev.target_grant_id === target.id,
  )
}

const taskGrant = grantMap.get('cap-440-task')
const sameAuthorRev = revMap.get('cap-441-revoke-task-same-author')
const coGrantorRev = revMap.get('cap-441-revoke-task-co-grantor')
const mirrorGrant = grantMap.get('cap-440-mirror')
const mirrorRev = revMap.get('cap-441-revoke-mirror-with-bridge-p')
const onboardGrant = grantMap.get('cap-440-onboard')
const onboardBackdatedRev = revMap.get('cap-441-revoke-onboard-backdated')
const grantorsPool = new Set([
  bundle.identities.owner_grantor.pubkey,
  bundle.identities.co_grantor.pubkey,
])

check(
  'same-author 441 revokes under both strict-same-author and grantor-pool folds',
  foldStrictSameAuthorOrderIndependent([taskGrant], [sameAuthorRev], bundle.evaluation_now).length === 0 &&
    foldGrantorPoolTimestampSorted([taskGrant], [sameAuthorRev], grantorsPool, bundle.evaluation_now).length === 0,
)
check(
  'mirror 441 carries bridge p-tag for #p-filtered relay subscriptions and revokes mirror 440',
  tagValue(mirrorRev, 'p') === bundle.identities.bridge_carrier.pubkey &&
    foldStrictSameAuthorOrderIndependent([mirrorGrant], [mirrorRev], bundle.evaluation_now).length === 0,
)
check(
  'backdated 441 (created_at < 440) revokes in order-independent fold vs survives in timestamp-sorted fold',
  onboardBackdatedRev.created_at < onboardGrant.created_at &&
    foldStrictSameAuthorOrderIndependent([onboardGrant], [onboardBackdatedRev], bundle.evaluation_now).length === 0 &&
    foldGrantorPoolTimestampSorted([onboardGrant], [onboardBackdatedRev], grantorsPool, bundle.evaluation_now).length === 1,
)
check(
  'co-grantor 441 (pubkey != 440.pubkey) is ignored by strict-same-author fold vs revokes in grantor-pool fold',
  coGrantorRev.pubkey !== taskGrant.pubkey &&
    foldStrictSameAuthorOrderIndependent([taskGrant], [coGrantorRev], bundle.evaluation_now).length === 1 &&
    foldGrantorPoolTimestampSorted([taskGrant], [coGrantorRev], grantorsPool, bundle.evaluation_now).length === 0,
)

console.log('\n5. Negative control vectors')
const negMap = new Map(bundle.negative_vectors.map((v) => [v.id, v]))

const negOutsider = negMap.get('neg-441-outsider-author')
check(
  'neg-441-outsider-author has valid sig but fails to revoke in both strict and grantor-pool folds',
  verifySignedNostrEvent(negOutsider.event) &&
    foldStrictSameAuthorOrderIndependent([taskGrant], [negOutsider.event], bundle.evaluation_now).length === 1 &&
    foldGrantorPoolTimestampSorted([taskGrant], [negOutsider.event], grantorsPool, bundle.evaluation_now).length === 1,
)

const negSelfShadow = negMap.get('neg-440-self-shadow')
check(
  'neg-440-self-shadow has valid sig & scope but fails self-delegation guard (p === pubkey)',
  verifySignedNostrEvent(negSelfShadow.event) &&
    tagValue(negSelfShadow.event, 'p') === negSelfShadow.event.pubkey,
)

const negSelfOnboard = negMap.get('neg-440-self-onboard')
check(
  'neg-440-self-onboard has valid sig & scope but fails self-delegation guard (p === pubkey)',
  verifySignedNostrEvent(negSelfOnboard.event) &&
    tagValue(negSelfOnboard.event, 'p') === negSelfOnboard.event.pubkey,
)

const negBadSalt = negMap.get('neg-440-bad-salt-nonhex')
const badSaltTag = negBadSalt.event.tags.find((t) => t[0] === 'da-scope')
let strictSaltThrew = false
try {
  strictDaScopeHash(negBadSalt.subject_preimage, badSaltTag[2])
} catch {
  strictSaltThrew = true
}
check(
  'neg-440-bad-salt-nonhex rejected by strict hex validators while matching loose Buffer.from(salt, "hex") truncation',
  verifySignedNostrEvent(negBadSalt.event) &&
    strictSaltThrew &&
    !relayPolicySaltValid(badSaltTag[2]) &&
    nodeLooseDaScopeHash(negBadSalt.subject_preimage, badSaltTag[2]) === badSaltTag[1],
)

const negNpub = negMap.get('neg-440-npub-unnormalized-subject')
const npubScopeTag = negNpub.event.tags.find((t) => t[0] === 'da-scope')
const decodedNpub = nip19.decode(negNpub.unnormalized_subject)
check(
  'neg-440-npub-unnormalized-subject fails normalized 64-hex scopeMatches while matching raw npub preimage',
  verifySignedNostrEvent(negNpub.event) &&
    decodedNpub.type === 'npub' &&
    decodedNpub.data === negNpub.expected_normalized_subject &&
    strictDaScopeHash(negNpub.expected_normalized_subject, npubScopeTag[2]) !== npubScopeTag[1] &&
    strictDaScopeHash(negNpub.unnormalized_subject, npubScopeTag[2]) === npubScopeTag[1],
)

const negExpired = negMap.get('neg-440-expired')
check(
  'neg-440-expired has valid sig but is rejected at evaluation_now',
  verifySignedNostrEvent(negExpired.event) &&
    isExpiredStrictNip40(negExpired.event, bundle.evaluation_now) &&
    foldStrictSameAuthorOrderIndependent([negExpired.event], [], bundle.evaluation_now).length === 0,
)

const negMalformedExp = negMap.get('neg-440-malformed-expiration')
check(
  'neg-440-malformed-expiration has valid sig and fails closed under strict NIP-40 expiration check',
  verifySignedNostrEvent(negMalformedExp.event) &&
    isExpiredStrictNip40(negMalformedExp.event, bundle.evaluation_now) &&
    foldStrictSameAuthorOrderIndependent([negMalformedExp.event], [], bundle.evaluation_now).length === 0,
)

const negTampered = negMap.get('neg-440-tampered-sig')
check(
  'neg-440-tampered-sig keeps matching event id hash but fails BIP-340 Schnorr signature verification',
  getEventHash(negTampered.event) === negTampered.event.id &&
    !verifySignedNostrEvent(negTampered.event),
)

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
