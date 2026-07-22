// smoke.mjs — live-relay smoke test for NIP-XX Scoped Data Grants.
//
//   node smoke.mjs --local                     # in-memory relay (CI-safe)
//   node smoke.mjs                             # default public relays
//   node smoke.mjs wss://relay.damus.io ...    # explicit relays
//
// Exits 0 if all checks pass, 1 otherwise. Uses throwaway keys and dummy
// data only — everything published is ciphertext, but treat public relays
// as public.

import { generateSecretKey, getPublicKey, nip59 } from 'nostr-tools'
import { Relay } from './relay.mjs'
import { LiveRelay, LocalRelay } from './liverelay.mjs'
import {
  KIND_DATA_SET, KIND_GRANT,
  newScopeKey, publishScope, grant, rotateScope, deleteScope, addressBook,
  receiveGrants, latestGrants, fetchScope,
  saveGrantIndex, loadGrantIndex, toReceivedEntry, fromReceivedEntry,
} from './nipxx.mjs'

const DEFAULT_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']

const args = process.argv.slice(2)
const local = args.includes('--local')
const urls = args.filter(a => a.startsWith('wss://'))
const relay = local
  ? new LocalRelay(new Relay())
  : new LiveRelay(urls.length ? urls : DEFAULT_RELAYS)

console.log(local ? 'mode: LOCAL (in-memory relay)' : `mode: LIVE → ${relay.urls.join(', ')}`)

const sleep = (ms) => new Promise(r => setTimeout(r, ms))
const settle = () => local ? Promise.resolve() : sleep(1500)   // propagation

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}

const alice = generateSecretKey()
const bob = generateSecretKey()
const carol = generateSecretKey()

// ------------------------------------------------------------------ scenario
try {
  console.log('\n1. Publish two scopes')
  const basic = { scopeId: 'sx' + Math.random().toString(36).slice(2, 8), generation: 1, scopeKey: newScopeKey() }
  const personal = { scopeId: 'sp' + Math.random().toString(36).slice(2, 8), generation: 1, scopeKey: newScopeKey() }
  const basicPayload = { name: 'Basic', fields: { display_name: 'SmokeAlice', email: 'a@test.invalid' } }
  let personalPayload = { name: 'Personal', fields: { tel: '+1 555 0100' } }

  const p1 = await publishScope(relay, alice, { ...basic, payload: basicPayload })
  const p2 = await publishScope(relay, alice, { ...personal, payload: personalPayload })
  check('kind-30440 accepted by relay(s)', p1.acks > 0 && p2.acks > 0, `${p1.acks}/${p1.of} acks`)

  console.log('\n2. Deliver grants (gift-wrapped)')
  const g1 = await grant(relay, alice, getPublicKey(bob), { ...basic, scopeName: 'Basic' })
  const g2 = await grant(relay, alice, getPublicKey(bob), { ...personal, scopeName: 'Personal' })
  const g3 = await grant(relay, alice, getPublicKey(carol), { ...basic, scopeName: 'Basic' })
  check('kind-1059 gift wraps accepted', [g1, g2, g3].every(g => g.acks > 0))
  await settle()

  console.log('\n3. Grantees dereference')
  const bobBook = await addressBook(relay, bob)
  const carolBook = await addressBook(relay, carol)
  check('Bob decrypts both scopes',
    bobBook.filter(e => e.status === 'ok').length === 2)
  check('Carol decrypts basic only',
    carolBook.length === 1 && carolBook[0].status === 'ok'
    && carolBook[0].data.fields.display_name === 'SmokeAlice')

  console.log('\n4. Live update')
  personalPayload = { name: 'Personal', fields: { tel: '+506 555 0142' } }
  await publishScope(relay, alice, { ...personal, payload: personalPayload })
  await settle()
  const bobBook2 = await addressBook(relay, bob)
  const tel = bobBook2.find(e => e.scopeName === 'Personal')?.data?.fields?.tel
  check('Bob sees updated phone with no new grant', tel === '+506 555 0142', tel)

  console.log('\n5. Revoke Carol (rotate basic)')
  await rotateScope(relay, alice, {
    scopeId: basic.scopeId, generation: basic.generation,
    payload: basicPayload, scopeName: 'Basic',
    survivors: [getPublicKey(bob)],
  })
  await settle()
  const bobBook3 = await addressBook(relay, bob)
  const carolBook3 = await addressBook(relay, carol)
  check('Bob (re-granted) still reads basic',
    bobBook3.find(e => e.scopeName === 'Basic')?.status === 'ok')
  check('Carol detects stale after rotation',
    carolBook3[0]?.status === 'stale')

  console.log('\n6. Bob re-wraps the rotated key to Carol (grant authentication)')
  // Bob — a survivor holding a first-party gen-2 grant — re-delivers Alice's
  // scope key to revoked Carol: a kind-440 rumor *Bob* authors whose a-tag
  // still names Alice's scope. The authenticated author (the seal pubkey,
  // Bob) differs from the a-tag publisher (Alice), so per SPEC "Grant
  // authentication" readers flag it `rewrapped` and the default address book
  // rejects it — the revocation is not silently undone unless a client opts
  // into an explicit delegation policy.
  const bobBasic = latestGrants(await receiveGrants(relay, bob)).find(g => g.scopeId === basic.scopeId)
  const rewrap = nip59.wrapEvent({
    kind: KIND_GRANT,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['a', `${KIND_DATA_SET}:${getPublicKey(alice)}:${basic.scopeId}`, ''],
      ['v', String(bobBasic.generation)],
    ],
    content: JSON.stringify({ scope_key: Buffer.from(bobBasic.scopeKey).toString('base64'), scope_name: 'Basic' }),
  }, bob, getPublicKey(carol))
  const r1 = await relay.publish(rewrap)
  check('re-wrap gift wrap accepted', r1.acks > 0)
  await settle()
  const carolGrants = await receiveGrants(relay, carol)
  const rewrapped = carolGrants.find(g => g.author === getPublicKey(bob))
  check('Carol sees rewrapped:true (author Bob, a-tag publisher Alice)',
    rewrapped?.rewrapped === true && rewrapped?.publisher === getPublicKey(alice)
    && carolGrants.filter(g => g.author === getPublicKey(alice)).every(g => g.rewrapped === false))
  const carolBook5 = await addressBook(relay, carol)
  check('default address book rejects the re-wrap (Carol stays revoked)',
    carolBook5.every(e => !e.rewrapped)
    && carolBook5.find(e => e.scopeId === basic.scopeId)?.status === 'stale')
  const carolBook5b = await addressBook(relay, carol, { allowRewrapped: true })
  const viaRewrap = carolBook5b.find(e => e.rewrapped)
  check('allowRewrapped surfaces it, distinct author intact — and it decrypts',
    viaRewrap?.status === 'ok' && viaRewrap?.author === getPublicKey(bob)
    && viaRewrap?.data?.fields?.display_name === 'SmokeAlice')

  console.log('\n7. Grant Index (kind 10440)')
  const i1 = await saveGrantIndex(relay, bob, {
    issued: [],
    received: latestGrants(await receiveGrants(relay, bob)).map(g => toReceivedEntry(g, 'alice')),
  })
  check('kind-10440 accepted by relay(s)', i1.acks > 0, `${i1.acks}/${i1.of} acks`)
  await settle()
  // Recovery path: only the nsec — no gift-wrap scan, no local state.
  const recovered = await Promise.all(
    (await loadGrantIndex(relay, bob)).received.map(fromReceivedEntry)
      .map(async g => ({ ...g, ...await fetchScope(relay, g) })))
  check('address book recovered from index alone',
    recovered.length === 2 && recovered.every(e => e.status === 'ok')
    && recovered.some(e => e.data?.fields?.tel === '+506 555 0142'))

  console.log('\n8. Delete a scope (tombstone + NIP-09)')
  const d1 = await deleteScope(relay, alice, { scopeId: personal.scopeId, generation: 1 })
  check('tombstone + kind-5 accepted', d1.acks > 0)
  await settle()
  const bobBook4 = await addressBook(relay, bob)
  check('deleted scope reads as revoked, not ok',
    bobBook4.find(e => e.scopeId === personal.scopeId)?.status !== 'ok')

  console.log('\n9. Rollback detection (u high-water mark)')
  // A withholding relay still serving an older copy is invisible to
  // decryption alone: the old event is validly signed and the unrotated key
  // still fits. The signed `u` tag plus a persisted (v, u) high-water mark
  // turns that silent pin into an explicit 'rollback' — detectable, not
  // impossible (a relay can always withhold; SPEC Security 7). The frozen
  // relay is simulated in-memory in both modes; `relay` stays live on live.
  const roll = { scopeId: 'sr' + Math.random().toString(36).slice(2, 8), generation: 1, scopeKey: newScopeKey() }
  const frozen = new LocalRelay(new Relay())   // the withholding relay: only ever sees u=1
  await publishScope(frozen, alice, { ...roll, payload: { name: 'Roll', fields: { note: 'old' } }, seq: 1 })
  await publishScope(relay, alice, { ...roll, payload: { name: 'Roll', fields: { note: 'new' } }, seq: 2 })
  await settle()
  const rollRec = { publisher: getPublicKey(alice), scopeId: roll.scopeId, generation: 1, scopeKey: roll.scopeKey }
  const seen = await fetchScope(relay, rollRec)
  check('fetch reports the content sequence (u=2) to persist as high-water',
    seen.status === 'ok' && seen.seq === 2 && seen.data.fields.note === 'new')
  const pinned = await fetchScope(frozen, rollRec)
  check('without a mark the rolled-back copy reads ok (the pin is silent)',
    pinned.status === 'ok' && pinned.data.fields.note === 'old')
  const caught = await fetchScope(frozen, rollRec, { highWater: { v: seen.generation, u: seen.seq } })
  check('with the (v,u) high-water mark the downgrade reads rollback',
    caught.status === 'rollback' && caught.seq === 1)
  const entry = toReceivedEntry({ ...rollRec, seq: seen.seq }, 'alice')
  check('high-water (v,u) round-trips through a Grant Index received entry',
    entry.u === 2 && fromReceivedEntry(entry).seq === 2)

  console.log('\n10. Multi-relay fanout prefers max (u, created_at)')
  // Relay A holds u=2; relay B holds only u=1 — published later, so B's
  // copy carries the NEWER created_at (a skewed device clock, a fuzzed
  // timestamp). created_at ordering would surface B's stale copy; the
  // fanout comparator trusts the signed content sequence first. In-memory
  // relay pair in both modes for determinism — on live, step 9 already
  // drives the same comparator through LiveRelay.query.
  const A = new Relay(), B = new Relay()
  const fan = { scopeId: 'sf' + Math.random().toString(36).slice(2, 8), generation: 1, scopeKey: newScopeKey() }
  await publishScope(new LocalRelay(A), alice, { ...fan, payload: { name: 'Fan', fields: { note: 'current' } }, seq: 2 })
  await publishScope(new LocalRelay(B), alice, { ...fan, payload: { name: 'Fan', fields: { note: 'lagging' } }, seq: 1 })
  const fanRec = { publisher: getPublicKey(alice), scopeId: fan.scopeId, generation: 1, scopeKey: fan.scopeKey }
  const merged = await fetchScope(new LocalRelay(A, B), fanRec)
  check("fanout across A+B returns u=2 despite B's newer created_at",
    merged.status === 'ok' && merged.seq === 2 && merged.data.fields.note === 'current')
  const behind = await fetchScope(new LocalRelay(B), fanRec, { highWater: { v: 1, u: merged.seq } })
  check('relay B alone, below the fanout-learned mark, reads rollback',
    behind.status === 'rollback')

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  relay.close()
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mSmoke test aborted:\x1b[0m', err.message)
  relay.close()
  process.exit(1)
}
