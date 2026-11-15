// Frontier C7 done-when: "No deployed tag is undefined." Checks the closed capability registry
// (capability-registry.json, CAPABILITY-GRANTS.md section 4) against the frozen q-076 fixtures:
// every capability vector's da-cap is registered and carries the registry's required tags and
// grantee rule; the unknown-cap negative is not registered; and the registry lists no cap that
// the fixtures leave unexercised. Offline, no keys.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const registry = JSON.parse(readFileSync(new URL('./capability-registry.json', import.meta.url), 'utf8'))
const fixtures = JSON.parse(readFileSync(new URL('./fixtures/capability-grants-v1.json', import.meta.url), 'utf8'))
const caps = registry.capabilities
const tag = (event, name) => event.tags.filter(t => t[0] === name)
let checks = 0
const ok = (cond, msg) => { assert.ok(cond, msg); checks++ }

ok(registry.closed === true, 'the registry is closed')
const seen = new Set()
for (const v of fixtures.capability_grant_vectors) {
  const e = v.event, cap = tag(e, 'da-cap')
  ok(e.kind === 440 && cap.length === 1, `${v.id}: one da-cap on a kind 440`)
  const name = cap[0][1], spec = caps[name]
  ok(spec, `${v.id}: da-cap "${name}" is registered`)
  ok(spec.status === v.issuance_status || (spec.status === 'issuance_disabled' && /disabled/i.test(v.issuance_status)) ||
     (spec.status === 'dormant' && /dormant|gated/i.test(v.issuance_status)) || spec.status === 'active',
     `${v.id}: registry status agrees with the fixture`)
  for (const t of spec.required_tags) ok(tag(e, t).length === 1, `${v.id}: carries required tag "${t}"`)
  ok(tag(e, 'p').length === 1 && tag(e, 'da-scope').length === 1, `${v.id}: one p and one da-scope`)
  ok(/^[0-9a-f]{32}$/.test(tag(e, 'da-scope')[0][2]), `${v.id}: salt is 32 lowercase hex`)
  if (spec.grantee_not_grantor) ok(tag(e, 'p')[0][1] !== e.pubkey, `${v.id}: grantee differs from grantor`)
  seen.add(name)
}
for (const name of Object.keys(caps)) ok(seen.has(name), `registered cap "${name}" has a fixture vector`)

const unknown = fixtures.negative_vectors.find(v => v.id === 'neg-440-unknown-cap')
ok(unknown && !caps[tag(unknown.event, 'da-cap')[0][1]], 'the unknown-cap negative is not registered')
for (const id of ['neg-440-self-shadow', 'neg-440-self-onboard']) {
  const v = fixtures.negative_vectors.find(x => x.id === id)
  const spec = caps[tag(v.event, 'da-cap')[0][1]]
  ok(spec.grantee_not_grantor && tag(v.event, 'p')[0][1] === v.event.pubkey, `${id}: violates the registry's grantee rule`)
}
const badSalt = fixtures.negative_vectors.find(v => v.id === 'neg-440-bad-salt-nonhex')
ok(!/^[0-9a-f]{32}$/.test(tag(badSalt.event, 'da-scope')[0][2]), 'neg-440-bad-salt-nonhex fails the profile salt rule')

// The normative table and the JSON must list the same caps.
const doc = readFileSync(new URL('./CAPABILITY-GRANTS.md', import.meta.url), 'utf8')
const section = doc.slice(doc.indexOf('## 4. Capability registry'), doc.indexOf('### 4.1'))
const docCaps = [...section.matchAll(/^\| `([a-z+-]+)` \|/gm)].map(m => m[1]).filter(c => c !== 'da-cap')
assert.deepEqual(docCaps.sort(), Object.keys(caps).sort(), 'CAPABILITY-GRANTS.md section 4 lists exactly the registry caps'); checks++

console.log(`capability registry: ${checks}/${checks} checks passed`)
