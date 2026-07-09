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
  newScopeKey, publishScope, grant, addressBook,
  receiveGrants, latestGrants, fetchScope,
  saveGrantIndex, loadGrantIndex, toReceivedEntry, fromReceivedEntry,
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

  console.log('\n3. JS rotates its scope key → Go detects supersession')
  await publishScope(relay, alice, { ...scope, generation: 2, scopeKey: newScopeKey(),
    payload: { name: 'Basic', fields: { display_name: 'InteropAlice' } } })
  await settle()
  goBook = go('book', '-sk', hex(bob)) ?? []
  check('Go marks JS-rotated scope stale',
    goBook.find(e => e.publisher === getPublicKey(alice))?.status === 'stale')

  console.log('\n4. Go writes the Grant Index → JS recovers from it')
  go('index-save', '-sk', hex(bob), '-petname', 'friends')
  await settle()
  const received = (await loadGrantIndex(relay, bob)).received.map(fromReceivedEntry)
  const jsRecovered = await Promise.all(received.map(async g => ({ ...g, ...await fetchScope(relay, g) })))
  check('JS recovers address book from Go-written kind-10440',
    jsRecovered.some(e => e.publisher === getPublicKey(gopher) && e.status === 'ok'))

  console.log('\n5. JS rewrites the Grant Index → Go recovers from it')
  await sleep(2000)  // replaceable events: ensure a strictly newer created_at
  await saveGrantIndex(relay, bob, {
    issued: [],
    received: latestGrants(await receiveGrants(relay, bob)).map(g => toReceivedEntry(g, 'friends')),
  })
  await settle()
  const goRecovered = go('index-book', '-sk', hex(bob)) ?? []
  check('Go recovers address book from JS-written kind-10440',
    goRecovered.some(e => e.publisher === getPublicKey(gopher) && e.status === 'ok'))

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  relay.close()
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mInterop test aborted:\x1b[0m', err.message)
  relay.close()
  process.exit(1)
}
