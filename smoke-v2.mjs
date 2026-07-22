// smoke-v2.mjs — smoke test for the EXPERIMENTAL v2 track (SPEC-v2.md):
// Attenuable Scoped Data Grants, kind 31440 + 442.
//
//   node smoke-v2.mjs --local                  # in-memory relay (CI-safe; npm run smoke:v2)
//   node smoke-v2.mjs                          # default public relays
//   node smoke-v2.mjs wss://relay.damus.io …   # explicit relays
//
// What must be TRUE of the construction, not merely of the API:
//   - a full grant reads everything; an attenuated grant reads its subset and
//     CANNOT read the rest — asserted as decrypt (MAC) failure on the actual
//     ciphertexts under every key the holder could try, not merely as an
//     absent field in a result object;
//   - per-field rotation strands exactly the revoked field-holder: the same
//     holder's OTHER fields, other attenuated holders, and root holders
//     (grant-free, by derivation) are all untouched;
//   - onward re-wraps can only narrow, and arrive flagged `rewrapped` with
//     v1's default-reject policy;
//   - root rotation expels whole capabilities and re-labels the wire;
//   - the v1 reader (unmodified nipxx.mjs) walks the SAME relay and the SAME
//     mixed 1059 inbox and neither errors nor surfaces any v2 artifact.
//
// Exits 0 if all checks pass, 1 otherwise. Throwaway keys and dummy data.

import { generateSecretKey, getPublicKey, nip44 } from 'nostr-tools'
import { Relay } from './relay.mjs'
import { LiveRelay, LocalRelay } from './liverelay.mjs'
import {
  KIND_DATA_SET_V2, KIND_GRANT_V2,
  newRootKey, deriveFieldKey, deriveManifestKey, deriveLabel,
  publishAttenuableScope, grantFields, attenuate, rotateField, rotateRoot,
  receiveGrantsV2, latestGrantsV2, fetchAttenuableScope, attenuableBook,
} from './nipxx-v2.mjs'
// The v1 lib appears ONLY as a coexistence witness: imported read-only, never
// modified — the assertion is that it ignores every v2 artifact unchanged.
import {
  publishScope as publishScopeV1, grant as grantV1,
  receiveGrants as receiveGrantsV1, addressBook as addressBookV1,
  newScopeKey as newScopeKeyV1,
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
const settle = () => local ? Promise.resolve() : sleep(1500)

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}

/** The adversarial primitive of this suite: does `key` decrypt `ciphertext`?
 *  Attenuation claims are proven by this returning FALSE against the real
 *  wire bytes — a MAC failure, not a politely absent field. */
const decrypts = (ciphertext, key) => {
  try { nip44.v2.decrypt(ciphertext, key); return true } catch { return false }
}

const alice = generateSecretKey()   // publisher
const bob = generateSecretKey()     // full (root) grantee
const carol = generateSecretKey()   // attenuated: email + tel
const dave = generateSecretKey()    // attenuated: tel only
const erin = generateSecretKey()    // attenuated: email only
const frank = generateSecretKey()   // receives carol's onward re-wrap

// ------------------------------------------------------------------ scenario
try {
  console.log('\n1. Publish an attenuable scope; grant the spectrum (full → subsets)')
  const scopeId = 'w2' + Math.random().toString(36).slice(2, 8)
  const root = { scopeId, rootGeneration: 1, rootKey: newRootKey() }
  let fields = {
    display_name: 'V2Alice',
    email: 'v2alice@test.invalid',
    tel: '+1 555 0100',
  }
  let gens = {}   // per-field generations, all 1
  const p1 = await publishAttenuableScope(relay, alice, { ...root, name: 'Personal', fields })
  check('kind-31440 accepted by relay(s)', p1.acks > 0, `${p1.acks}/${p1.of} acks`)
  // What the relay actually sees: opaque labels and ciphertext — the tags
  // carry hex labels (field names cannot appear: names aren't hex), and no
  // plaintext value survives anywhere in the signed event.
  check('wire leaks no field names in tags and no values anywhere',
    !JSON.stringify(p1.event.tags).match(/display_name|email|tel/)
    && !JSON.stringify(p1.event).includes('v2alice@test.invalid')
    && !JSON.stringify(p1.event).includes('555 0100'))
  check('vf tags carry per-field generations under derived labels',
    p1.event.tags.filter(t => t[0] === 'vf').length === 3
    && p1.event.tags.some(t => t[0] === 'vf' && t[1] === deriveLabel(root.rootKey, 'email') && t[2] === '1'))

  // Grants: Bob full; Carol {email, tel}; Dave {tel}; Erin {email}.
  const sub = (fs) => attenuate({ ...root, publisher: getPublicKey(alice), scopeName: 'Personal' }, fs)
  const g1 = await grantFields(relay, alice, getPublicKey(bob), { ...root, scopeName: 'Personal' })
  const g2 = await grantFields(relay, alice, getPublicKey(carol), sub(['email', 'tel']))
  const g3 = await grantFields(relay, alice, getPublicKey(dave), sub(['tel']))
  const g4 = await grantFields(relay, alice, getPublicKey(erin), sub(['email']))
  check('kind-442 gift wraps accepted', [g1, g2, g3, g4].every(g => g.acks > 0))

  // Coexistence seed (checked in step 7): the SAME publisher also runs a v1
  // scope over the SAME relay, granted to the SAME grantee — Bob's one 1059
  // inbox now mixes kind-440 and kind-442 rumors.
  const v1scope = { scopeId: 'v1' + Math.random().toString(36).slice(2, 8), generation: 1, scopeKey: newScopeKeyV1() }
  await publishScopeV1(relay, alice, { ...v1scope, payload: { name: 'V1Basic', fields: { note: 'plain v1 scope' } } })
  await grantV1(relay, alice, getPublicKey(bob), { ...v1scope, scopeName: 'V1Basic' })
  await settle()

  console.log('\n2. Full grant reads everything; attenuated grants read exactly their subset')
  const bobBook = await attenuableBook(relay, bob)
  const bobCap = bobBook.find(e => e.scopeId === scopeId)
  check('Bob (root) decrypts every field',
    bobCap?.status === 'ok'
    && bobCap.fields.display_name?.value === 'V2Alice'
    && bobCap.fields.email?.value === 'v2alice@test.invalid'
    && bobCap.fields.tel?.value === '+1 555 0100')
  const carolCap = latestGrantsV2(await receiveGrantsV2(relay, carol))[0]
  const carolView = await fetchAttenuableScope(relay, carolCap)
  check('Carol decrypts her granted fields (email, tel) and reads the manifest',
    carolView.status === 'ok' && carolView.name === 'Personal'
    && carolView.fields.email?.value === 'v2alice@test.invalid'
    && carolView.fields.tel?.value === '+1 555 0100')
  check('the non-granted field reads LOCKED — present in the manifest, no value surfaced',
    carolView.fields.display_name?.status === 'locked'
    && !('value' in carolView.fields.display_name))

  // The cryptographic teeth. Take the REAL ciphertext of display_name off
  // the wire and prove Carol's material cannot open it: not her subkeys, not
  // her manifest key, not anything HKDF-derivable from what she holds.
  const [ev1] = await relay.query({ kinds: [KIND_DATA_SET_V2], authors: [getPublicKey(alice)], '#d': [scopeId] })
  const dnCt = JSON.parse(ev1.content).f[deriveLabel(root.rootKey, 'display_name')]
  check('locked field is a decrypt FAILURE, not an absence: every key Carol holds fails the MAC',
    !decrypts(dnCt, carolCap.subkeys.email.key)
    && !decrypts(dnCt, carolCap.subkeys.tel.key)
    && !decrypts(dnCt, carolCap.manifestKey))
  check('nor can Carol DERIVE her way in: treating held subkeys as roots yields only garbage keys',
    !decrypts(dnCt, deriveFieldKey(carolCap.subkeys.email.key, 'display_name', 1))
    && !decrypts(dnCt, deriveFieldKey(carolCap.manifestKey, 'display_name', 1))
    && decrypts(dnCt, deriveFieldKey(root.rootKey, 'display_name', 1)))  // control: the real key fits
  const erinView = await fetchAttenuableScope(relay, latestGrantsV2(await receiveGrantsV2(relay, erin))[0])
  check('Erin (email only) reads email; tel and display_name locked',
    erinView.fields.email?.value === 'v2alice@test.invalid'
    && erinView.fields.tel?.status === 'locked'
    && erinView.fields.display_name?.status === 'locked')

  console.log('\n3. Live update: one publish, every holder current, no new grants')
  fields = { ...fields, email: 'v2alice+new@test.invalid' }
  await publishAttenuableScope(relay, alice, { ...root, name: 'Personal', fields, fieldGenerations: gens })
  await settle()
  const carolView2 = await fetchAttenuableScope(relay, carolCap)
  check('Carol sees the updated email through her existing grant',
    carolView2.fields.email?.value === 'v2alice+new@test.invalid'
    && carolView2.fields.tel?.value === '+1 555 0100')

  console.log('\n4. Per-field rotation: revoke Carol from tel only (survivor: Dave)')
  // Rotate ONE leaf. Carol keeps email; Dave is re-granted tel; Erin holds
  // an unrelated field and is untouched; Bob holds the root and derives the
  // new tel key from the manifest — nobody re-wraps him anything.
  const rot = await rotateField(relay, alice, {
    ...root, name: 'Personal', fields, fieldGenerations: gens,
    field: 'tel', survivors: [getPublicKey(dave)], scopeName: 'Personal',
  })
  gens = rot.fieldGenerations
  await settle()
  check('tel generation bumped to 2; vf tag shows it under the same label; email vf untouched',
    gens.tel === 2
    && (await relay.query({ kinds: [KIND_DATA_SET_V2], authors: [getPublicKey(alice)], '#d': [scopeId] }))[0]
        .tags.some(t => t[0] === 'vf' && t[1] === deriveLabel(root.rootKey, 'tel') && t[2] === '2'))
  const carolView3 = await fetchAttenuableScope(relay, carolCap)
  check('Carol: tel now STALE (her subkey generation is below the manifest), email still ok',
    carolView3.fields.tel?.status === 'stale'
    && carolView3.fields.email?.value === 'v2alice+new@test.invalid')
  const [ev2] = await relay.query({ kinds: [KIND_DATA_SET_V2], authors: [getPublicKey(alice)], '#d': [scopeId] })
  const telCt = JSON.parse(ev2.content).f[deriveLabel(root.rootKey, 'tel')]
  check('the revocation is cryptographic: her old tel subkey fails the MAC on the fresh ciphertext',
    !decrypts(telCt, carolCap.subkeys.tel.key)
    && decrypts(telCt, rot.subkey.key))   // control: the rotated key fits
  const daveCap = latestGrantsV2(await receiveGrantsV2(relay, dave))[0]
  check('Dave (survivor): original grant + one-field re-grant MERGE to the rotated subkey',
    daveCap.subkeys.tel.v === 2
    && (await fetchAttenuableScope(relay, daveCap)).fields.tel?.value === '+1 555 0100')
  check('Erin (other field) is untouched — still exactly one grant, still reads email',
    (await receiveGrantsV2(relay, erin)).length === 1
    && (await fetchAttenuableScope(relay, latestGrantsV2(await receiveGrantsV2(relay, erin))[0]))
        .fields.email?.value === 'v2alice+new@test.invalid')
  const bobView = await fetchAttenuableScope(relay, bobCap)
  check('Bob (root) rides through the rotation with NO new grant: derives tel@2 from the manifest',
    (await receiveGrantsV2(relay, bob)).length === 1
    && bobView.fields.tel?.value === '+1 555 0100' && bobView.fields.tel?.v === 2)

  console.log('\n5. Onward attenuation: a subset-holder re-wraps a NARROWER subset')
  // Carol {email, tel@stale} re-wraps {email} to Frank. Author (Carol) ≠
  // a-tag publisher (Alice): flagged rewrapped, default-rejected — v1's
  // grant-authentication policy verbatim. What v2 changes is the bound:
  // Carol can hand on at most what she holds.
  const narrowed = attenuate(carolCap, ['email'])
  await grantFields(relay, carol, getPublicKey(frank), { ...narrowed, scopeName: 'Personal' })
  await settle()
  const frankGrants = await receiveGrantsV2(relay, frank)
  check('Frank sees rewrapped:true (author Carol, a-tag publisher Alice)',
    frankGrants.length === 1 && frankGrants[0].rewrapped === true
    && frankGrants[0].author === getPublicKey(carol)
    && frankGrants[0].publisher === getPublicKey(alice))
  check('default policy rejects the re-wrap (empty book without allowRewrapped)',
    latestGrantsV2(frankGrants).length === 0)
  const frankCap = latestGrantsV2(frankGrants, { allowRewrapped: true })[0]
  const frankView = await fetchAttenuableScope(relay, frankCap)
  check('opted in, Frank reads exactly the narrowed subset: email ok, everything else locked',
    frankView.fields.email?.value === 'v2alice+new@test.invalid'
    && frankView.fields.tel?.status === 'locked'
    && frankView.fields.display_name?.status === 'locked')
  check("Frank's material cannot open what Carol didn't pass on (MAC failure on the wire bytes)",
    !decrypts(dnCt, frankCap.subkeys.email.key) && !decrypts(telCt, frankCap.subkeys.email.key))
  let widened = null
  try { widened = attenuate(carolCap, ['email', 'display_name']) } catch (e) { widened = e }
  check('widening is impossible: attenuating to a never-held field throws (no key exists to give)',
    widened instanceof Error && /cannot widen/.test(widened.message))

  console.log('\n6. Root rotation: full expulsion, everything re-keys, the wire re-labels')
  const oldRootKey = root.rootKey
  const rr = await rotateRoot(relay, alice, {
    scopeId, rootGeneration: 1, name: 'Personal', fields,
    survivors: [{ pubkey: getPublicKey(bob) }, { pubkey: getPublicKey(dave), fields: ['tel'] }],
    scopeName: 'Personal',
  })
  await settle()
  check('root generation Lamport-bumped to 2; per-field generations restart at 1',
    rr.rootGeneration === 2
    && (await fetchAttenuableScope(relay, latestGrantsV2(await receiveGrantsV2(relay, bob))[0]))
        .fields.tel?.v === 1)
  const [ev3] = await relay.query({ kinds: [KIND_DATA_SET_V2], authors: [getPublicKey(alice)], '#d': [scopeId] })
  check('every wire label changed with the root (longitudinal per-field trail severed)',
    deriveLabel(rr.rootKey, 'tel') !== deriveLabel(oldRootKey, 'tel')
    && JSON.parse(ev3.content).f[deriveLabel(rr.rootKey, 'tel')] != null
    && JSON.parse(ev3.content).f[deriveLabel(oldRootKey, 'tel')] == null)
  check('the old manifest key is dead too: MAC failure on the new manifest',
    !decrypts(JSON.parse(ev3.content).m, deriveManifestKey(oldRootKey))
    && decrypts(JSON.parse(ev3.content).m, deriveManifestKey(rr.rootKey)))
  check('non-survivors are expelled: Carol, Erin, and re-wrapped Frank all read stale',
    (await fetchAttenuableScope(relay, carolCap)).status === 'stale'
    && (await fetchAttenuableScope(relay, latestGrantsV2(await receiveGrantsV2(relay, erin))[0])).status === 'stale'
    && (await fetchAttenuableScope(relay, latestGrantsV2(await receiveGrantsV2(relay, frank), { allowRewrapped: true })[0])).status === 'stale')
  const bobCap2 = latestGrantsV2(await receiveGrantsV2(relay, bob))[0]
  const daveCap2 = latestGrantsV2(await receiveGrantsV2(relay, dave))[0]
  check('survivors continue: Bob full at the new root, Dave attenuated to tel@1 under it',
    bobCap2.rootGeneration === 2
    && (await fetchAttenuableScope(relay, bobCap2)).fields.email?.value === 'v2alice+new@test.invalid'
    && daveCap2.rootGeneration === 2 && !daveCap2.rootKey
    && (await fetchAttenuableScope(relay, daveCap2)).fields.tel?.value === '+1 555 0100'
    && (await fetchAttenuableScope(relay, daveCap2)).fields.email?.status === 'locked')

  console.log('\n7. Counter discipline (v/u verbatim from v1) and v1/v2 coexistence')
  // u bumped on every publish: initial, update, field rotation, root rotation.
  const fin = await fetchAttenuableScope(relay, bobCap2)
  check('content sequence u advanced across all four publishes; fetch reports (v, u) to persist',
    fin.generation === 2 && fin.seq === 4)
  // Rollback detection, v1's rule against a withholding relay (in-memory in
  // both modes, as in the v1 suite).
  const frozen = new LocalRelay(new Relay())
  const roll = { scopeId: 'r2' + Math.random().toString(36).slice(2, 8), rootGeneration: 1, rootKey: newRootKey() }
  await publishAttenuableScope(frozen, alice, { ...roll, name: 'Roll', fields: { note: 'old' }, seq: 1 })
  const rollCap = { publisher: getPublicKey(alice), scopeId: roll.scopeId, rootGeneration: 1, rootKey: roll.rootKey }
  check('below the persisted (v, u) high-water mark the served copy reads rollback',
    (await fetchAttenuableScope(frozen, rollCap)).status === 'ok'
    && (await fetchAttenuableScope(frozen, rollCap, { highWater: { v: 1, u: 2 } })).status === 'rollback')

  // The coexistence claim, both directions, over the SAME relay and the SAME
  // mixed inbox. The v1 lib here is the unmodified nipxx.mjs.
  const bobV1Grants = await receiveGrantsV1(relay, bob)
  check('v1 reader scans the mixed inbox without error and surfaces ONLY v1 grants',
    bobV1Grants.length === 1 && bobV1Grants[0].scopeId === v1scope.scopeId)
  const bobV1Book = await addressBookV1(relay, bob)
  check('v1 address book: exactly the v1 scope, ok, correct payload — no v2 artifact',
    bobV1Book.length === 1 && bobV1Book[0].status === 'ok'
    && bobV1Book[0].data.fields.note === 'plain v1 scope')
  const bobV2Grants = await receiveGrantsV2(relay, bob)
  check('v2 reader, same inbox: only v2 grants (kind-440 rumors skipped)',
    bobV2Grants.every(g => g.scopeId === scopeId))
  const bobV2Book = await attenuableBook(relay, bob)
  check('v2 book: exactly the v2 scope — the two tracks share relays and inboxes without contact',
    bobV2Book.length === 1 && bobV2Book[0].scopeId === scopeId && bobV2Book[0].status === 'ok')

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  relay.close()
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mSmoke test aborted:\x1b[0m', err.message)
  relay.close()
  process.exit(1)
}
