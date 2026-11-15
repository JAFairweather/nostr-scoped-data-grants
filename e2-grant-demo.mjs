// E2 draft: an offline, throwaway issue → verify → attenuate walkthrough.
// Run: npm run demo:e2-grant. Nothing is sent to a public relay.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { generateSecretKey, getEventHash, getPublicKey, nip44, verifyEvent } from 'nostr-tools'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { Relay } from './relay.mjs'
import { LocalRelay } from './liverelay.mjs'
import {
  newRootKey, deriveLabel, publishAttenuableScope, grantFields, attenuate,
  receiveGrantsV2, latestGrantsV2, fetchAttenuableScope,
} from './nipxx-v2.mjs'

const fixture = JSON.parse(readFileSync(new URL('./fixtures/capability-grants-v1.json', import.meta.url)))
const task = fixture.capability_grant_vectors.find(v => v.id === 'cap-440-task')
assert.ok(task, 'PR 20 task fixture exists')
const signed = structuredClone(task.event) // fresh object avoids signature-verification caches
assert.equal(getEventHash(signed), signed.id)
assert.equal(verifyEvent(signed), true)
const classifiesAsCapability = ev => ev.kind === 440
  && !ev.tags.some(t => t[0] === 'a')
  && ['p', 'da-scope', 'da-cap'].every(name => ev.tags.filter(t => t[0] === name).length === 1)
assert.equal(classifiesAsCapability(signed), true)
assert.equal(signed.tags.find(t => t[0] === 'da-cap')[1], 'task')
const scope = signed.tags.find(t => t[0] === 'da-scope')
assert.match(scope[2], /^[0-9a-f]{32}$/)
assert.equal(scope[1], bytesToHex(sha256(concatBytes(
  utf8ToBytes('waggle/da-scope/v1'), Uint8Array.of(0),
  utf8ToBytes(task.subject_preimage), hexToBytes(scope[2]),
))))
const duplicate = fixture.negative_vectors.find(v => v.id === 'neg-440-duplicate-da-cap')
assert.ok(duplicate, 'PR 21 duplicate-tag fixture exists')
assert.equal(verifyEvent(structuredClone(duplicate.event)), true)
assert.equal(classifiesAsCapability(duplicate.event), false)
console.log('PR 20/21 fixtures: signed 440 and da-scope verify; ambiguous duplicate cap is refused.')

// The fixture above is the deployed authority profile. The following grant is
// the separate experimental data-grant profile from SPEC-v2.md: kind 442 in a
// NIP-59 wrap, with field-key attenuation. It does not grant task authority.
const relay = new LocalRelay(new Relay())
const alice = generateSecretKey()
const carol = generateSecretKey()
const frank = generateSecretKey()
const root = {
  scopeId: 'e2-demo', rootGeneration: 1, rootKey: newRootKey(),
  publisher: getPublicKey(alice), scopeName: 'Demo',
}
await publishAttenuableScope(relay, alice, {
  ...root, name: 'Demo', fields: { email: 'alice@test.invalid', tel: '+1 555 0100' },
})
await grantFields(relay, alice, getPublicKey(carol), root)
const carolGrants = latestGrantsV2(await receiveGrantsV2(relay, carol))
assert.equal(carolGrants.length, 1)
assert.equal(carolGrants[0].author, root.publisher)
assert.equal(carolGrants[0].rewrapped, false)
assert.ok(carolGrants[0].rootKey)
const carolView = await fetchAttenuableScope(relay, carolGrants[0])
assert.equal(carolView.fields.email.value, 'alice@test.invalid')
assert.equal(carolView.fields.tel.value, '+1 555 0100')
console.log('Issue and verify: Carol receives Alice’s first-party full grant and reads both fields.')

const emailOnly = attenuate(carolGrants[0], ['email'])
assert.equal(emailOnly.rootKey, undefined)
assert.deepEqual(Object.keys(emailOnly.subkeys), ['email'])
await grantFields(relay, carol, getPublicKey(frank), emailOnly)
const frankRaw = await receiveGrantsV2(relay, frank)
assert.equal(frankRaw.length, 1)
assert.equal(frankRaw[0].author, getPublicKey(carol))
assert.equal(frankRaw[0].rewrapped, true)
assert.equal(latestGrantsV2(frankRaw).length, 0) // default policy rejects re-wraps
const [frankCap] = latestGrantsV2(frankRaw, { allowRewrapped: true })
assert.ok(frankCap)
const frankView = await fetchAttenuableScope(relay, frankCap)
assert.equal(frankView.fields.email.value, 'alice@test.invalid')
assert.equal(frankView.fields.tel.status, 'locked')
assert.equal('value' in frankView.fields.tel, false)
assert.throws(() => attenuate(frankCap, ['tel']), /cannot widen/)
const [dataset] = await relay.query({ kinds: [31440], authors: [root.publisher], '#d': [root.scopeId] })
const telCiphertext = JSON.parse(dataset.content).f[deriveLabel(root.rootKey, 'tel')]
for (const key of [frankCap.manifestKey, frankCap.subkeys.email.key]) {
  assert.throws(() => nip44.v2.decrypt(telCiphertext, key))
}
console.log('Attenuate: Carol re-wraps email only; Frank’s tel is locked by ciphertext, and widening fails.')
console.log('E2 grant demo passed (local relay only).')
