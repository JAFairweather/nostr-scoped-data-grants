// demo.mjs — end-to-end walkthrough of Permissioned Private Data Sharing.
//
//   Alice publishes two encrypted scopes of contact data.
//   Bob (close friend) is granted both; Carol (acquaintance) gets "basic" only.
//   Alice changes her phone number → Bob sees it live, no re-share.
//   Alice revokes Carol → key rotation; Carol keeps history, loses the future.
//
// Run: node demo.mjs

import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { Relay } from './relay.mjs'
import {
  newScopeKey, publishScope, grant, rotateScope, addressBook,
  receiveGrants, latestGrants, fetchScope,
  saveGrantIndex, loadGrantIndex, toIssuedEntry, toReceivedEntry, fromReceivedEntry,
} from './nipxx.mjs'

// The lib awaits its relay, and a sync in-memory relay satisfies await
// trivially — same code path here as against live wss:// relays.
const relay = new Relay()

const alice = generateSecretKey()
const bob = generateSecretKey()
const carol = generateSecretKey()

const h = (s) => console.log(`\n\x1b[1m── ${s} ${'─'.repeat(Math.max(0, 60 - s.length))}\x1b[0m`)
const show = (who, result) => console.log(
  `  ${who} → ${result.status === 'ok'
    ? JSON.stringify(result.data.fields)
    : `\x1b[33m${result.status.toUpperCase()}\x1b[0m (key generation superseded — last-known data should be shown greyed out)`}`)

h('1. Alice publishes two encrypted scopes')
// Opaque d-tags: the relay must not learn her disclosure structure.
const basic    = { scopeId: 'x1f4q9', generation: 1, scopeKey: newScopeKey() }
const personal = { scopeId: 'p8w2m5', generation: 1, scopeKey: newScopeKey() }

let basicPayload    = { name: 'Basic',    fields: { display_name: 'Alice', email: 'alice@example.com' } }
let personalPayload = { name: 'Personal', fields: { tel: '+1 203 555 0114', adr: '85 Shoreline Rd, Milford CT' } }

await publishScope(relay, alice, { ...basic, payload: basicPayload })
await publishScope(relay, alice, { ...personal, payload: personalPayload })
console.log('  Published kind-30440 events. Relay stores ciphertext only.')

h('2. Grants: Bob gets both scopes, Carol gets basic only')
await grant(relay, alice, getPublicKey(bob),   { ...basic,    scopeName: 'Basic' })
await grant(relay, alice, getPublicKey(bob),   { ...personal, scopeName: 'Personal' })
await grant(relay, alice, getPublicKey(carol), { ...basic,    scopeName: 'Basic' })
console.log('  Grants delivered as NIP-59 gift wraps — ephemeral sender keys,')
console.log('  fuzzed timestamps. The relay cannot see who granted whom.')

h('3. Each grantee dereferences their grants')
for (const [name, secret] of [['Bob  ', bob], ['Carol', carol]])
  for (const entry of await addressBook(relay, secret)) show(`${name} [${entry.scopeName}]`, entry)

h('4. Live update: Alice changes her phone number')
personalPayload = { ...personalPayload, fields: { ...personalPayload.fields, tel: '+506 8888 0142' } }
await publishScope(relay, alice, { ...personal, payload: personalPayload })
console.log('  One republish under the SAME scope key. No per-grantee action.')
for (const entry of await addressBook(relay, bob)) show('Bob  ', entry)

h('5. Revocation: Alice rotates Carol out of "basic"')
const rotated = await rotateScope(relay, alice, {
  scopeId: basic.scopeId, generation: basic.generation,
  payload: basicPayload, scopeName: 'Basic',
  survivors: [getPublicKey(bob)],           // everyone except Carol
})
Object.assign(basic, rotated)
console.log(`  New key, generation ${rotated.generation}; data republished; Bob re-granted.`)
for (const [name, secret] of [['Bob  ', bob], ['Carol', carol]])
  for (const entry of await addressBook(relay, secret)) show(`${name} [${entry.scopeName}]`, entry)

h('6. Grant Index: everything recoverable from the nsec alone')
// Alice's `issued` side is the authoritative record a rotation needs;
// Bob's `received` side IS his address book. Each is one replaceable
// kind-10440 event, NIP-44 encrypted to its owner.
await saveGrantIndex(relay, alice, {
  issued: [
    toIssuedEntry({ ...basic,    scopeName: 'Basic'    }, [getPublicKey(bob)]),   // Carol rotated out
    toIssuedEntry({ ...personal, scopeName: 'Personal' }, [getPublicKey(bob)]),
  ],
  received: [],
})
await saveGrantIndex(relay, bob, {
  issued: [],
  received: latestGrants(await receiveGrants(relay, bob)).map(g => toReceivedEntry(g, 'alice')),
})
console.log('  Alice and Bob each published their kind-10440 index.')

// A brand-new client holding only Bob's nsec: no gift-wrap scan, no local
// state — load the index, dereference, done.
console.log('  Bob signs in on a new device with only his nsec:')
for (const g of (await loadGrantIndex(relay, bob)).received.map(fromReceivedEntry))
  show('Bob (new device)', await fetchScope(relay, g))

h("7. The adversarial relay operator's complete view")
console.table(relay.observerView())
console.log('  Kinds, sizes (NIP-44 padded), opaque d-tags, ephemeral wrap keys.')
console.log('  No plaintext, no grant graph, no scope semantics. QED.')
