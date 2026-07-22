// interop.mjs — cross-implementation test: JS (nostr-tools) ↔ Go (go-nostr).
// The two implementations share nothing but SPEC.md and the relays; each
// side must read what the other wrote. This is the credential for a NIPs PR.
//
//   npm run interop      (builds go/nipxx, then runs this against live relays)
//
// Throwaway keys and dummy data only.

import { execFileSync } from 'node:child_process'
import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { LiveRelay } from './liverelay.mjs'
import {
  newScopeKey, publishScope, grant, rotateScope, addressBook,
  receiveGrants, latestGrants,
  saveGrantIndex, loadGrantIndex, toReceivedEntry,
} from './nipxx.mjs'

const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']
const relay = new LiveRelay(RELAYS)
console.log(`interop: JS (nostr-tools) ↔ Go (go-nostr) via ${RELAYS.join(', ')}`)

const hex = (b) => Buffer.from(b).toString('hex')
const b64 = (b) => Buffer.from(b).toString('base64')
const sleep = (ms) => new Promise(r => setTimeout(r, ms))
const settle = () => sleep(1500)

/** Run the Go CLI; parse its JSON output. */
const go = (...args) => JSON.parse(
  execFileSync('./go/nipxx', [...args, '-relays', RELAYS.join(',')],
    { encoding: 'utf8', cwd: import.meta.dirname }).trim() || 'null')

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}

const alice  = generateSecretKey()  // JS-side publisher
const gopher = generateSecretKey()  // Go-side publisher
const bob    = generateSecretKey()  // grantee, driven from both sides

try {
  console.log('\n1. JS publishes and grants → Go dereferences')
  const scope = { scopeId: 'ix' + Math.random().toString(36).slice(2, 8), generation: 1, scopeKey: newScopeKey() }
  await publishScope(relay, alice, { ...scope, payload: { name: 'Basic', fields: { display_name: 'InteropAlice', email: 'a@test.invalid' } } })
  await grant(relay, alice, getPublicKey(bob), { ...scope, scopeName: 'Basic' })
  await settle()
  let goBook = go('book', '-sk', hex(bob)) ?? []
  const fromJs = goBook.find(e => e.publisher === getPublicKey(alice))
  check('Go decrypts JS-published scope via JS-issued grant',
    fromJs?.status === 'ok' && fromJs?.data?.fields?.display_name === 'InteropAlice')

  console.log('\n2. Go publishes and grants → JS dereferences')
  const gScopeId = 'gx' + Math.random().toString(36).slice(2, 8)
  const gKey = newScopeKey()
  go('publish', '-sk', hex(gopher), '-scope', gScopeId, '-gen', '1', '-key', b64(gKey),
    '-payload', JSON.stringify({ name: 'GoBasic', fields: { display_name: 'InteropGopher', email: 'g@test.invalid' } }))
  go('grant', '-sk', hex(gopher), '-to', getPublicKey(bob), '-scope', gScopeId, '-gen', '1',
    '-key', b64(gKey), '-name', 'GoBasic')
  await settle()
  const jsBook = await addressBook(relay, bob)
  const fromGo = jsBook.find(e => e.publisher === getPublicKey(gopher))
  check('JS decrypts Go-published scope via Go-issued grant',
    fromGo?.status === 'ok' && fromGo?.data?.fields?.display_name === 'InteropGopher')
  // SPEC "Grant authentication": both readers recover the same authenticated
  // grant author (the NIP-59 seal pubkey) — Go reading the JS-issued grant
  // attributes it to Alice, JS reading the Go-issued grant attributes it to
  // Gopher, and each equals its a-tag publisher (first-party).
  check('Go and JS agree on grant author identity (author == a-tag publisher)',
    fromJs?.author === getPublicKey(alice) && fromGo?.author === getPublicKey(gopher))
  // SPEC "Freshness and rollback detection": the content sequence rides the
  // signed `u` tag, so each reader recovers it without decryption. JS
  // published u=1 in step 1 (per-process auto-seq); Go published u=1 in
  // step 2 (-seq default); each side reads the other's.
  check('Go and JS agree on the content sequence (u) each other published',
    fromJs?.seq === 1 && fromGo?.seq === 1)

  console.log('\n3. JS rotates its scope key → Go detects supersession')
  await publishScope(relay, alice, { ...scope, generation: 2, scopeKey: newScopeKey(),
    payload: { name: 'Basic', fields: { display_name: 'InteropAlice' } } })
  await settle()
  goBook = go('book', '-sk', hex(bob)) ?? []
  // A rotation is also a publish, so JS's auto-seq bumped u to 2 — Go must
  // read the rotated event's sequence along with the supersession.
  check('Go marks JS-rotated scope stale and reads its bumped u=2',
    goBook.find(e => e.publisher === getPublicKey(alice))?.status === 'stale'
    && goBook.find(e => e.publisher === getPublicKey(alice))?.seq === 2)

  console.log('\n4. Go writes the Grant Index → JS recovers from it')
  go('index-save', '-sk', hex(bob), '-petname', 'friends')
  await settle()
  // Go's index-save records the inbox cursor next to the received cache
  // (SPEC "Discovering new grants"); JS addressBook({ index }) warm-starts
  // from the cache and drives its incremental wrap scan off the Go-written
  // cursor — the P4 cursor crossing implementations in one direction.
  const goIndex = await loadGrantIndex(relay, bob)
  const jsRecovered = await addressBook(relay, bob, { index: goIndex })
  check('JS recovers address book from Go-written kind-10440 (inbox cursor honored)',
    goIndex.inbox?.since > 0
    && jsRecovered.some(e => e.publisher === getPublicKey(gopher) && e.status === 'ok'))

  console.log('\n5. JS rewrites the Grant Index → Go recovers from it')
  await sleep(2000)  // replaceable events: ensure a strictly newer created_at
  const all = await receiveGrants(relay, bob)
  await saveGrantIndex(relay, bob, {
    issued: [],
    received: latestGrants(all).map(g => toReceivedEntry(g, 'friends')),
    inbox: all.cursor,  // cache + cursor in one write, per SPEC
  })
  await settle()
  const goRecovered = go('index-book', '-sk', hex(bob)) ?? []
  check('Go recovers address book from JS-written kind-10440',
    goRecovered.some(e => e.publisher === getPublicKey(gopher) && e.status === 'ok'))

  console.log('\n6. JS grants a new scope after the index snapshot → Go catches up incrementally')
  // The new wrap's created_at is NIP-59-fuzzed — up to two days behind the
  // checkpoint Go reads from the JS-written cursor. Go's incremental scan
  // reaches the overlap window behind the checkpoint and dedups the old
  // wraps by id, so it must surface exactly this late grant on top of the
  // warm cache: the P4 cursor crossing implementations in the other
  // direction, against real randomized timestamps on live relays.
  const late = { scopeId: 'il' + Math.random().toString(36).slice(2, 8), generation: 1, scopeKey: newScopeKey() }
  await publishScope(relay, alice, { ...late, payload: { name: 'Late', fields: { display_name: 'InteropLate' } } })
  await grant(relay, alice, getPublicKey(bob), { ...late, scopeName: 'Late' })
  await settle()
  const caught = go('index-book', '-sk', hex(bob)) ?? []
  check('Go index-book honors the JS-written inbox cursor and discovers the new grant',
    caught.find(e => e.scopeId === late.scopeId)?.status === 'ok'
    && caught.some(e => e.publisher === getPublicKey(gopher) && e.status === 'ok'))

  console.log('\n7. JS moves a scope to a fresh d at rotation → unmodified Go follows')
  // Metadata hardening (SPEC "Metadata-hardening profile", item 1): the d
  // rotates WITH the key, the new address riding in the same gift wrap as
  // the re-granted key. Deliberately NO Go-side change exists for this step
  // — that is the compatibility claim: a reader that merely implements
  // grants + fetch follows the move with zero new code, reads the restarted
  // content sequence (u=1) under the new identity, and sees the stranded
  // old address as ordinary generation supersession (stale).
  const dNew = 'im' + Math.random().toString(36).slice(2, 8)
  await rotateScope(relay, alice, {
    scopeId: late.scopeId, generation: 1,
    payload: { name: 'Late', fields: { display_name: 'InteropLate' } },
    scopeName: 'Late', survivors: [getPublicKey(bob)], newScopeId: dNew,
  })
  await settle()
  const movedBook = go('book', '-sk', hex(bob)) ?? []
  const movedTo = movedBook.find(e => e.scopeId === dNew)
  check('Go follows the JS d-rotation via the re-grant: new d ok at v=2, restarted u=1',
    movedTo?.status === 'ok' && movedTo?.generation === 2 && movedTo?.seq === 1
    && movedTo?.data?.fields?.display_name === 'InteropLate')
  check('Go reads the stranded old address as ordinary supersession (stale)',
    movedBook.find(e => e.scopeId === late.scopeId)?.status === 'stale')

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  relay.close()
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mInterop test aborted:\x1b[0m', err.message)
  relay.close()
  process.exit(1)
}
