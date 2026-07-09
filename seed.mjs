// seed.mjs — publish a throwaway demo graph to live relays for the Nontact
// UI, then print the nsec to sign in with. Dummy data only (.invalid, 555
// numbers); everything protocol-level is ciphertext on the wire.
//
//   node seed.mjs        # then: npm run web → paste the printed nsec
//
// The seed also prints an --update command that republishes Alice's Personal
// scope with a new phone number — run it, click Refresh in Nontact, and
// watch the live-update property with no re-grant.

import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from 'nostr-tools'
import { LiveRelay } from './liverelay.mjs'
import { newScopeKey, publishScope, grant, saveGrantIndex, toIssuedEntry } from './nipxx.mjs'

const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']
const relay = new LiveRelay(RELAYS)
const now = () => Math.floor(Date.now() / 1000)
const ev = (sk, kind, tags, content) =>
  relay.publish(finalizeEvent({ kind, created_at: now(), tags, content }, sk))

const args = process.argv.slice(2)
if (args[0] === '--update') {
  const [, skHex, scopeId, keyB64] = args
  const sk = Uint8Array.from(skHex.match(/../g), h => parseInt(h, 16))
  const tel = '+1 555 0' + String(100 + Math.floor(Math.random() * 900))
  await publishScope(relay, sk, {
    scopeId, generation: 1,
    scopeKey: Uint8Array.from(atob(keyB64), c => c.charCodeAt(0)),
    payload: { name: 'Personal', fields: {
      tel: [{ value: tel, label: 'mobile' }],
      adr: [{ value: '85 Shoreline Rd, Milford CT', label: 'home' }],
      bday: '--03-14',
    } },
  })
  console.log(`republished Personal under the same key — tel is now ${tel}`)
  console.log('click Refresh in Nontact; no new grant was issued')
  relay.close()
  process.exit(0)
}

const you = generateSecretKey()
const alice = generateSecretKey()   // follows you back, shares two scopes + one rotated-away
const carol = generateSecretKey()   // followed, shares nothing

// Pace the burst: public relays rate-limit, and a same-second republish of
// an addressable event loses the NIP-01 created_at tie ("have newer event").
const pause = (ms) => new Promise(r => setTimeout(r, ms))

console.log(`seeding demo graph → ${RELAYS.join(', ')}`)

console.log('  profiles (kind 0)')
await ev(alice, 0, [], JSON.stringify({ name: 'Alice Ferrous', about: 'Nontact demo — shares two scopes with you' }))
await ev(carol, 0, [], JSON.stringify({ name: 'Carol Nickel', about: 'Nontact demo — shares nothing' }))
await ev(you, 0, [], JSON.stringify({ name: 'Nontact Demo User' }))

console.log('  follow lists (kind 3): you → alice, carol; alice → you')
await ev(you, 3, [['p', getPublicKey(alice)], ['p', getPublicKey(carol)]], '')
await ev(alice, 3, [['p', getPublicKey(you)]], '')

console.log('  alice publishes scopes and grants them to you')
const rand = () => Math.random().toString(36).slice(2, 8)
const basic = { scopeId: 'nb' + rand(), generation: 1, scopeKey: newScopeKey() }
const personal = { scopeId: 'np' + rand(), generation: 1, scopeKey: newScopeKey() }
await publishScope(relay, alice, { ...basic, payload: { name: 'Basic', fields: {
  display_name: 'Alice Ferrous',
  email: [{ value: 'alice@ferrous.invalid', label: 'personal' }],
  url: 'https://ferrous.invalid',
} } })
await publishScope(relay, alice, { ...personal, payload: { name: 'Personal', fields: {
  tel: [{ value: '+1 555 0114', label: 'mobile' }],
  adr: [{ value: '85 Shoreline Rd, Milford CT', label: 'home' }],
  bday: '--03-14',
} } })
await grant(relay, alice, getPublicKey(you), { ...basic, scopeName: 'Basic' })
await grant(relay, alice, getPublicKey(you), { ...personal, scopeName: 'Personal' })

console.log('  …plus one scope granted, then rotated away (stale for you)')
const work = { scopeId: 'nw' + rand(), generation: 1, scopeKey: newScopeKey() }
const workPayload = { name: 'Work', fields: { org: 'Ferrous Industries', title: 'CTO' } }
await publishScope(relay, alice, { ...work, payload: workPayload })
await grant(relay, alice, getPublicKey(you), { ...work, scopeName: 'Work' })
await pause(1200)   // next second, so the rotated event wins replacement
await publishScope(relay, alice, { ...work, generation: 2, scopeKey: newScopeKey(), payload: workPayload })
// no re-grant to you → your Work grant is superseded

console.log('  your own scope + grant index, so "Your card" starts populated')
const mine = { scopeId: 'ny' + rand(), generation: 1, scopeKey: newScopeKey() }
await publishScope(relay, you, { ...mine, payload: { name: 'Personal', fields: {
  display_name: 'Nontact Demo User',
  tel: [{ value: '+1 555 0199', label: 'mobile' }],
  email: [{ value: 'you@nontact.invalid', label: 'personal' }],
} } })
await grant(relay, you, getPublicKey(alice), { ...mine, scopeName: 'Personal' })
await saveGrantIndex(relay, you, {
  issued: [toIssuedEntry({ ...mine, scopeName: 'Personal' }, [getPublicKey(alice)])],
  received: [],
})

const hex = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
const b64 = (b) => btoa(String.fromCharCode(...b))
console.log('\nSign in to Nontact with this throwaway key:\n')
console.log('  ' + nip19.nsecEncode(you))
console.log('\nDemo cheat sheet (throwaway identities):')
console.log(`  alice npub: ${nip19.npubEncode(getPublicKey(alice))}   sk-hex: ${hex(alice)}`)
console.log(`  carol npub: ${nip19.npubEncode(getPublicKey(carol))}   sk-hex: ${hex(carol)}`)
console.log('  → share your scope with carol from the UI, then verify with the Go CLI:')
console.log('      cd go && ./nipxx book -sk <carol-sk-hex>')
console.log('\nTo demo a live update (then click Refresh in Nontact):\n')
console.log(`  node seed.mjs --update ${hex(alice)} ${personal.scopeId} '${b64(personal.scopeKey)}'\n`)
relay.close()
