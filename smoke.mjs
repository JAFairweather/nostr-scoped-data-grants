// smoke.mjs — live-relay smoke test for NIP-XX Scoped Data Grants.
//
//   node smoke.mjs --local                     # in-memory relay (CI-safe)
//   node smoke.mjs                             # default public relays
//   node smoke.mjs wss://relay.damus.io ...    # explicit relays
//
// Exits 0 if all checks pass, 1 otherwise. Uses throwaway keys and dummy
// data only — everything published is ciphertext, but treat public relays
// as public.

import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, nip44, nip59 } from 'nostr-tools'
import { Relay } from './relay.mjs'
import { LiveRelay, LocalRelay } from './liverelay.mjs'
import {
  KIND_DATA_SET, KIND_GRANT, WRAP_OVERLAP,
  newScopeKey, publishScope, grant, rotateScope, deleteScope, addressBook,
  receiveGrants, latestGrants, fetchScope, padTo, jitterFetch,
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

/** Pass-through relay recording every query filter, so a test can see
 *  whether a scan was incremental (the 1059 filter carried `since`)
 *  without instrumenting the lib. Works over LocalRelay and LiveRelay. */
const spy = (inner) => ({
  filters: [],
  publish: (e) => inner.publish(e),
  query(f) { this.filters.push(f); return inner.query(f) },
})

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

  console.log('\n11. Incremental grantee inbox (warm start + since cursor)')
  // Grants share the 1059 inbox with NIP-17 DMs and the inner kind is
  // encrypted, so the relay can never be asked for "grants only" — what P4
  // bounds is the scan, via the inbox cursor. The correctness hazard is
  // NIP-59's timestamp fuzz: a wrap delivered AFTER a scan can be
  // timestamped up to two days BEFORE everything that scan saw, so a naive
  // since = checkpoint silently loses it. Deterministic here: the late wrap
  // is hand-built with created_at pinned one hour behind the checkpoint.
  const full = await receiveGrants(relay, bob)
  const cursor = full.cursor
  const bobWraps = await relay.query({ kinds: [1059], '#p': [getPublicKey(bob)] })
  check('full scan returns the cursor to persist (since = max wrap created_at)',
    cursor.since === Math.max(...bobWraps.map(w => w.created_at))
    && cursor.ids.length === bobWraps.length)
  // Persist cache + cursor in ONE index write (a cursor ahead of its cache
  // would hide grants), then warm-start from the round-tripped index.
  await saveGrantIndex(relay, bob, {
    issued: [],
    received: latestGrants(full).map(g => toReceivedEntry(g, 'alice')),
    inbox: cursor,
  })
  await settle()
  const idx = await loadGrantIndex(relay, bob)
  check('inbox cursor round-trips through the Grant Index', idx.inbox?.since === cursor.since)
  const spyWarm = spy(relay)
  const warmBook = await addressBook(spyWarm, bob, { index: idx })
  const shape = (b) => b.map(e => `${e.publisher.slice(0, 8)}:${e.scopeId}:${e.status}`).sort().join(' ')
  check('warm start from the index equals the full-scan address book',
    shape(warmBook) === shape(await addressBook(relay, bob)))
  const warmSince = spyWarm.filters.find(f => f.kinds?.includes(1059))?.since
  check('warm-start wrap scan was incremental: 1059 filter carried since = checkpoint − overlap',
    warmSince === cursor.since - WRAP_OVERLAP)
  check('nothing new → every in-window wrap deduped by id, cursor unchanged',
    warmBook.cursor.since === cursor.since
    && [...warmBook.cursor.ids].sort().join() === [...cursor.ids].sort().join())

  // A grant "delivered" after the checkpoint but timestamped inside the
  // overlap window — nipxx's own giftWrap fuzzes randomly, so build the
  // wrap by hand (same NIP-59 construction) to pin created_at.
  const late = { scopeId: 'si' + Math.random().toString(36).slice(2, 8), generation: 1, scopeKey: newScopeKey() }
  await publishScope(relay, alice, { ...late, payload: { name: 'Inbox', fields: { note: 'late delivery' } } })
  const backTs = cursor.since - 3600
  const conv = nip44.v2.utils.getConversationKey
  const rumor = {
    pubkey: getPublicKey(alice), kind: KIND_GRANT, created_at: backTs,
    tags: [['a', `${KIND_DATA_SET}:${getPublicKey(alice)}:${late.scopeId}`, ''], ['v', '1']],
    content: JSON.stringify({ scope_key: Buffer.from(late.scopeKey).toString('base64'), scope_name: 'Inbox' }),
  }
  rumor.id = getEventHash(rumor)
  const seal = finalizeEvent({ kind: 13, created_at: backTs, tags: [],
    content: nip44.v2.encrypt(JSON.stringify(rumor), conv(alice, getPublicKey(bob))) }, alice)
  const eph = generateSecretKey()
  const lateWrap = finalizeEvent({ kind: 1059, created_at: backTs, tags: [['p', getPublicKey(bob)]],
    content: nip44.v2.encrypt(JSON.stringify(seal), conv(eph, getPublicKey(bob))) }, eph)
  await relay.publish(lateWrap)
  await settle()
  const naive = await relay.query({ kinds: [1059], '#p': [getPublicKey(bob)], since: cursor.since })
  check('naive since = checkpoint MISSES the backdated wrap (the bug P4 must not have)',
    !naive.some(w => w.id === lateWrap.id))
  const inc = await receiveGrants(relay, bob, { since: cursor.since, seenIds: cursor.ids })
  check('incremental scan (checkpoint − overlap) returns exactly the new grant',
    inc.length === 1 && inc[0].scopeId === late.scopeId
    && inc.cursor.since === cursor.since && inc.cursor.ids.includes(lateWrap.id))
  const spyMerge = spy(relay)
  const mergedBook = await addressBook(spyMerge, bob, { index: idx })
  check('merged warm book carries old and new scopes — still no full re-scan',
    mergedBook.find(e => e.scopeId === late.scopeId)?.data?.fields?.note === 'late delivery'
    && mergedBook.find(e => e.scopeId === basic.scopeId)?.status === 'ok'
    && spyMerge.filters.find(f => f.kinds?.includes(1059))?.since === cursor.since - WRAP_OVERLAP)
  const again = await receiveGrants(relay, bob, { since: inc.cursor.since, seenIds: inc.cursor.ids })
  check('overlapping re-scan double-processes nothing (dedup by wrap id)',
    again.length === 0 && again.cursor.since === inc.cursor.since)

  console.log('\n12. Metadata hardening (d rotates with the key; padding; jitter)')
  // Weakness 7: every payload is ciphertext, yet a relay watching a STABLE
  // opaque d accumulates the scope's whole update history ("this scope
  // changed 47 times"). Rotation already re-grants every survivor, so
  // moving the scope to a fresh d at the same time is free — the new
  // address rides in the same gift wrap as the new key — and the old
  // address is stranded behind a tombstone that tells a revoked watcher
  // nothing. The in-memory observer below records what an adversarial
  // operator sees, in both modes; the grantee flow runs against `relay`.
  const observer = new Relay()
  const observed = {   // every publish lands on the main relay AND the observer
    publish: async (e) => { observer.publish(e); return relay.publish(e) },
    query: (f) => relay.query(f),
  }
  const dave = generateSecretKey(), erin = generateSecretKey()
  const dOld = 'sm' + Math.random().toString(36).slice(2, 8)
  const dNew = 'sn' + Math.random().toString(36).slice(2, 8)
  const meta = { scopeId: dOld, generation: 1, scopeKey: newScopeKey() }
  await publishScope(observed, alice, { ...meta, payload: { name: 'Meta', fields: { display_name: 'HardAlice', note: 'generation one' } } })  // u=1
  await grant(relay, alice, getPublicKey(dave), { ...meta, scopeName: 'Meta' })
  await grant(relay, alice, getPublicKey(erin), { ...meta, scopeName: 'Meta' })
  await publishScope(observed, alice, { ...meta, payload: { name: 'Meta', fields: { display_name: 'HardAlice', note: 'generation one, edited' } } })  // u=2: history accrues under dOld
  await settle()
  const daveFull = await receiveGrants(relay, dave)
  await saveGrantIndex(relay, dave, {   // pre-move warm cache: OLD address + cursor
    issued: [],
    received: latestGrants(daveFull).map(g => toReceivedEntry(g, 'alice')),
    inbox: daveFull.cursor,
  })
  const before = observer.observerView().filter(e => e.kind === KIND_DATA_SET).map(e => e.d)
  // Revoke Erin AND move the scope: the same rotation call, one extra option.
  const moved = await rotateScope(observed, alice, {
    scopeId: dOld, generation: 1,
    payload: { name: 'Meta', fields: { display_name: 'HardAlice', note: 'generation two' } },
    scopeName: 'Meta', survivors: [getPublicKey(dave)], newScopeId: dNew,
  })
  await settle()
  check('d-rotation returns the moved identity: new scopeId, bumped v, RESTARTED u',
    moved.scopeId === dNew && moved.generation === 2 && moved.seq === 1)
  const daveBook = await addressBook(relay, dave)
  const followed = daveBook.find(e => e.scopeId === dNew)
  check('survivor follows to the new address seamlessly via the re-grant (same wrap as the key)',
    followed?.status === 'ok' && followed?.generation === 2 && followed?.scopeName === 'Meta'
    && followed?.data?.fields?.note === 'generation two')
  const erinBook = await addressBook(relay, erin)
  check('revoked watcher of the tombstoned address learns nothing: stale, no data, no pointer to the new d',
    erinBook.length === 1 && erinBook[0].scopeId === dOld
    && erinBook[0].status === 'stale' && erinBook[0].data == null)
  // High-water marks are keyed by (pubkey, d): the moved scope is a NEW
  // identity, starting with no mark, so its restarted u=1 reads ok…
  const freshFetch = await fetchScope(relay, followed)
  check('fresh identity reads ok at u=1 — no mark carries over, no false rollback',
    freshFetch.status === 'ok' && freshFetch.generation === 2 && freshFetch.seq === 1)
  // …and here is why SPEC forbids carrying a mark across the d change: the
  // old identity's tombstone shares the bumped v=2 with a HIGHER u (3), so
  // a carried mark would misread the restarted sequence as a downgrade.
  const carried = await fetchScope(relay, followed, { highWater: { v: 2, u: 3 } })
  check('a (wrongly) carried old-identity mark would false-flag rollback — hence per-(pubkey,d) marks',
    carried.status === 'rollback')
  // The old identity stays monotone to the end: the tombstone bumped (v, u),
  // so against the old mark it reads supersession (stale), never rollback.
  const strand = await fetchScope(relay,
    { publisher: getPublicKey(alice), scopeId: dOld, generation: 1, scopeKey: meta.scopeKey },
    { highWater: { v: 1, u: 2 } })
  check('tombstone under the old d reads stale against the old mark (monotone, no rollback)',
    strand.status === 'stale' && strand.seq === 3)
  // P4 warm cache across the move: the cached entry names the OLD address;
  // the re-grant arrives through the ordinary incremental wrap scan and
  // supersedes it — same publisher, same scope_name lineage, next
  // generation, new a/d — with still no full re-scan.
  const daveIdx = await loadGrantIndex(relay, dave)
  const spyMove = spy(relay)
  const warmMoved = await addressBook(spyMove, dave, { index: daveIdx })
  check('warm cache: re-grant supersedes the cached old address — new d ok, old d stale, no full re-scan',
    warmMoved.find(e => e.scopeId === dNew)?.status === 'ok'
    && warmMoved.find(e => e.scopeId === dOld)?.status === 'stale'
    && spyMove.filters.find(f => f.kinds?.includes(1059))?.since === daveIdx.inbox.since - WRAP_OVERLAP)
  const after = observer.observerView().filter(e => e.kind === KIND_DATA_SET)
  check("observer's longitudinal view broke: the live scope's d changed across generations",
    before.includes(dOld) && !before.includes(dNew)
    && after.some(e => e.d === dNew) && after.some(e => e.d === dOld))
  // Padding to coarse buckets. NIP-44's own padding is fine-grained, so a
  // field edit can hop size classes; padTo pins differently sized payloads
  // into ONE publisher-chosen bucket. Construction is pure client side —
  // in-memory relay in both modes, asserting on the signed events.
  const padRelay = new LocalRelay(new Relay())
  const padKey = newScopeKey()
  const small = { name: 'Pad', fields: { note: 'short' } }
  const big = { name: 'Pad', fields: { note: 'x'.repeat(400) } }
  const rawS = await publishScope(padRelay, alice, { scopeId: 'pa1', generation: 1, scopeKey: newScopeKey(), payload: small })
  const rawB = await publishScope(padRelay, alice, { scopeId: 'pa2', generation: 1, scopeKey: newScopeKey(), payload: big })
  check('unpadded, the two payloads sit in different observable size classes (the leak)',
    rawS.event.content.length !== rawB.event.content.length)
  const padS = await publishScope(padRelay, alice, { scopeId: 'pa3', generation: 1, scopeKey: padKey, payload: padTo(small, 1024) })
  const padB = await publishScope(padRelay, alice, { scopeId: 'pa4', generation: 1, scopeKey: newScopeKey(), payload: padTo(big, 1024) })
  check('padTo(1024) puts both in one size class: equal ciphertext length',
    padS.event.content.length === padB.event.content.length)
  const padRec = { publisher: getPublicKey(alice), scopeId: 'pa3', generation: 1, scopeKey: padKey }
  const padded = await fetchScope(padRelay, padRec)
  check('padding is transparent to readers: fields intact, pad ignored',
    padded.status === 'ok' && padded.data.fields.note === 'short')
  // Fetch jitter: defer, then pass the result through untouched.
  const t0 = Date.now()
  const viaJitter = await jitterFetch(() => fetchScope(padRelay, padRec), 250)
  check('jitterFetch defers the fetch and passes the result through',
    viaJitter.status === 'ok' && viaJitter.data.fields.note === 'short' && Date.now() - t0 < 10_000)

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  relay.close()
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mSmoke test aborted:\x1b[0m', err.message)
  relay.close()
  process.exit(1)
}
