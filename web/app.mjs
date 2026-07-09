// app.mjs — Nontact: the emergent address book.
//
// Sharing is a matrix (contacts × scopes) and the UI exposes both axes:
//   - Address book (contact axis): each card shows what they share with you
//     AND what you share with them, with per-scope toggle chips — the natural
//     place for individual sharing decisions.
//   - My card (scope axis): each scope shows its audience, with a searchable
//     picker and an explicit one-time "share with all" bulk action.
// Cards for people you share with who share nothing back render ghosted —
// asymmetry is visible, not hidden.

import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { LiveRelay } from '../liverelay.mjs'
import {
  localSigner, newScopeKey, publishScope, grant, rotateScope, deleteScope,
  receiveGrants, latestGrants, fetchScope,
  loadGrantIndex, saveGrantIndex, toIssuedEntry, fromIssuedEntry,
} from '../nipxx.mjs'

const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']

// The field vocabulary: vCard 4.0 (RFC 6350) lowercase property names, per
// SPEC.md. Presentation + authoring convenience only — the wire format
// carries the bare names; icons never leave this client.
const FIELDS = {
  display_name: { icon: '', hint: 'name shown to grantees' },
  tel:   { icon: '📞', hint: 'phone' },
  email: { icon: '✉️', hint: 'email' },
  adr:   { icon: '🏠', hint: 'address' },
  url:   { icon: '🔗', hint: 'website' },
  bday:  { icon: '🎂', hint: 'birthday' },
  org:   { icon: '🏢', hint: 'organisation' },
  title: { icon: '💼', hint: 'role' },
  note:  { icon: '📝', hint: 'free text' },
}

// Default scopes, echoing SPEC.md's examples. No "Public" template:
// genuinely public data is what kind-0 profile metadata already broadcasts.
const TEMPLATES = {
  Basic:    [['display_name', ''], ['email', 'main'], ['url', '']],
  Personal: [['display_name', ''], ['tel', 'mobile'], ['email', 'personal'], ['adr', 'home'], ['bday', '']],
  Work:     [['org', ''], ['title', ''], ['email', 'work'], ['tel', 'work']],
  Custom:   [],
}

const $ = (id) => document.getElementById(id)
const esc = (s) => String(s).replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
const short = (pk) => { const n = nip19.npubEncode(pk); return n.slice(0, 12) + '…' + n.slice(-4) }

let relay, signer, me
let myIndex = { issued: [], received: [] }
let myScopes = []            // { scopeId, scopeName, generation, scopeKey, grantees, fields, draft? }
let profiles = new Map()     // pubkey → kind-0 profile
let knownContacts = []       // pubkeys in the address book
let bookState = null         // { follows, followers, sharedBy } — cached for re-render

// ------------------------------------------------------------------ login & tabs

function parseKey(input) {
  const s = input.trim()
  if (/^[0-9a-f]{64}$/i.test(s)) return Uint8Array.from(s.match(/../g), h => parseInt(h, 16))
  const { type, data } = nip19.decode(s)
  if (type !== 'nsec') throw new Error('not an nsec')
  return data
}

function parsePub(input) {
  const s = input.trim()
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase()
  const { type, data } = nip19.decode(s)
  if (type !== 'npub') throw new Error('not an npub')
  return data
}

function showTab(t) {
  for (const b of document.querySelectorAll('.tab')) b.classList.toggle('active', b.dataset.tab === t)
  $('book').style.display = t === 'book' ? '' : 'none'
  $('status').style.display = t === 'book' ? '' : 'none'
  $('mycard').style.display = t === 'card' ? '' : 'none'
  location.hash = t
}
for (const b of document.querySelectorAll('.tab')) b.onclick = () => showTab(b.dataset.tab)

// NIP-07: the browser extension holds the key; the page only ever sees
// signatures and nip44 plaintexts. Maps 1:1 onto the lib's signer interface.
function nip07Signer() {
  const n = window.nostr
  let pub = null
  return {
    getPublicKey: async () => (pub ??= await n.getPublicKey()),
    signEvent: (event) => n.signEvent(event),
    nip44Encrypt: (pk, plaintext) => n.nip44.encrypt(pk, plaintext),
    nip44Decrypt: (pk, ciphertext) => n.nip44.decrypt(pk, ciphertext),
  }
}

async function login(s, remember) {
  signer = s
  try { me = await signer.getPublicKey() }
  catch (err) { $('err').textContent = `extension refused: ${err.message}`; return }
  sessionStorage.setItem('nontact-login', remember)
  relay ??= new LiveRelay(RELAYS)
  $('login').style.display = 'none'
  $('me').style.display = 'flex'
  $('tabs').style.display = 'flex'
  showTab(location.hash === '#card' ? 'card' : 'book')
  const npub = nip19.npubEncode(me)
  $('my-npub').textContent = npub.slice(0, 12) + '…' + npub.slice(-4)
  $('my-npub').onclick = () => navigator.clipboard.writeText(npub)
  load()
}

const hexOf = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')

$('go').onclick = () => {
  try { const k = parseKey($('nsec').value); login(localSigner(k), hexOf(k)) }
  catch { $('err').textContent = 'Could not parse that — expected nsec1… or 64 hex chars.' }
}
$('nsec').onkeydown = (e) => { if (e.key === 'Enter') $('go').onclick() }
$('gen').onclick = () => { const k = generateSecretKey(); login(localSigner(k), hexOf(k)) }
$('nip07').onclick = () => {
  if (!window.nostr?.nip44) {
    $('err').textContent = 'No NIP-07 extension found (or it lacks nip44 support). Try Alby or nos2x.'
    return
  }
  login(nip07Signer(), 'nip07')
}
$('refresh').onclick = () => load()
$('logout').onclick = () => { sessionStorage.removeItem('nontact-login'); location.hash = ''; location.reload() }

const saved = sessionStorage.getItem('nontact-login')
if (saved === 'nip07') {
  // extensions inject window.nostr after page scripts run — give it a beat
  setTimeout(() => { if (window.nostr?.nip44) login(nip07Signer(), 'nip07') }, 250)
} else if (saved) {
  login(localSigner(Uint8Array.from(saved.match(/../g), h => parseInt(h, 16))), saved)
}

// ------------------------------------------------------------------ load

async function load() {
  $('status').textContent = `scanning ${RELAYS.length} relays for your graph, grants, and index…`
  $('book').innerHTML = ''
  try {
    const [myLists, followerLists, grants, index] = await Promise.all([
      relay.query({ kinds: [3], authors: [me], limit: 2 }),
      relay.query({ kinds: [3], '#p': [me], limit: 300 }),
      receiveGrants(relay, signer),
      loadGrantIndex(relay, signer),
    ])
    myIndex = index
    const follows = new Set((myLists[0]?.tags ?? []).filter(t => t[0] === 'p').map(t => t[1]))
    const followers = new Set(followerLists.map(e => e.pubkey))
    followers.delete(me)

    $('status').textContent = 'dereferencing shared data…'
    const drafts = myScopes.filter(s => s.draft)   // keep unpublished drafts across refresh
    const [shared, mine] = await Promise.all([
      Promise.all(latestGrants(grants).map(async g => ({ ...g, ...await fetchScope(relay, g) }))),
      Promise.all(myIndex.issued.map(async e => {
        const s = { ...fromIssuedEntry(e), publisher: me }
        const res = await fetchScope(relay, s)
        return { ...s, fields: res.status === 'ok' ? (res.data.fields ?? {}) : {}, lost: res.status !== 'ok' }
      })),
    ])
    myScopes = [...mine, ...drafts]
    const sharedBy = new Map()
    for (const s of shared) {
      if (!sharedBy.has(s.publisher)) sharedBy.set(s.publisher, [])
      sharedBy.get(s.publisher).push(s)
    }

    // The book includes everyone you granted to — even if they follow
    // nothing, share nothing, and never followed you back.
    knownContacts = [...new Set([
      ...follows, ...followers, ...sharedBy.keys(), ...myScopes.flatMap(s => s.grantees),
    ])].filter(p => p !== me)

    const wanted = [...new Set([...knownContacts, me])]
    profiles = new Map()
    if (wanted.length) {
      for (const ev of await relay.query({ kinds: [0], authors: wanted, limit: wanted.length * 3 }))
        if (!profiles.has(ev.pubkey)) {                     // query is newest-first
          try { profiles.set(ev.pubkey, JSON.parse(ev.content)) } catch { /* skip broken */ }
        }
    }

    bookState = { follows, followers, sharedBy }
    renderMine()
    render()
  } catch (err) {
    $('status').textContent = `relay error: ${err.message}`
  }
}

// ------------------------------------------------------------------ shared sharing actions

const contactName = (pk) => profiles.get(pk)?.display_name || profiles.get(pk)?.name || short(pk)

async function grantShare(s, pub) {
  await grant(relay, signer, pub, { ...s, relayHint: RELAYS[0] })
  if (!s.grantees.includes(pub)) s.grantees.push(pub)
  await syncIndex()
  renderMine()
  if (bookState) render()
}

async function revokeShare(s, pub) {
  if (!confirm(`Stop sharing "${s.scopeName}" with ${contactName(pub)}?\n\nThis rotates the scope key and re-grants the ${s.grantees.length - 1} other grantee(s). They keep what they already saw — that is physics — but get no future updates.`)) return
  const survivors = s.grantees.filter(p => p !== pub)
  const rotated = await rotateScope(relay, signer, {
    scopeId: s.scopeId, generation: s.generation, scopeName: s.scopeName,
    payload: { name: s.scopeName, fields: s.fields }, survivors,
  })
  Object.assign(s, { generation: rotated.generation, scopeKey: rotated.scopeKey, grantees: survivors })
  await syncIndex()
  renderMine()
  if (bookState) render()
}

// syncIndex: published scopes are the source of truth; `received` preserved.
const syncIndex = () => saveGrantIndex(relay, signer, {
  ...myIndex, issued: myScopes.filter(s => !s.draft).map(s => toIssuedEntry(s, s.grantees)),
})

// ------------------------------------------------------------------ my card

function editorRows(fields) {
  const rows = []
  for (const [type, v] of Object.entries(fields))
    for (const item of (Array.isArray(v) ? v : [v]))
      rows.push(item && typeof item === 'object'
        ? { type, value: item.value ?? '', label: item.label ?? '' }
        : { type, value: item, label: '' })
  return rows
}

// The same FIELDS vocabulary that renders contacts' cards renders yours:
// type a known vCard name and its icon appears, live.
const frowHtml = (r = { type: '', value: '', label: '' }) =>
  `<div class="frow">
     <span class="ficon">${FIELDS[r.type]?.icon || '·'}</span>
     <input class="ftype" list="fieldnames" placeholder="field" value="${esc(r.type)}">
     <input class="fvalue" placeholder="${esc(FIELDS[r.type]?.hint ?? 'value')}" value="${esc(r.value)}">
     <input class="flab" placeholder="label" value="${esc(r.label)}">
     <button class="del icon" title="remove field">×</button>
   </div>`

const TRASH_SVG = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none"
  stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m4 0-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6m5 5v6m4-6v6"/></svg>`

function collectFields(card) {
  const fields = {}
  for (const row of card.querySelectorAll('.frow')) {
    const type = row.querySelector('.ftype').value.trim()
    const value = row.querySelector('.fvalue').value.trim()
    const label = row.querySelector('.flab').value.trim()
    if (!type || !value) continue
    const item = label ? { value, label } : value
    fields[type] = type in fields ? [].concat(fields[type], item) : item
  }
  return fields
}

// Scope-axis audience view: current grantees + a searchable picker (datalist
// filters your contacts as you type; raw npub/hex also accepted) + explicit
// one-time bulk share. No chip-wall of every contact.
function shareBlock(s) {
  if (s.draft) return `<div class="msg">publish first, then share</div>`
  const chips = s.grantees.map(pk =>
    `<span class="chip" data-pub="${pk}">${esc(contactName(pk))}<button class="unshare" title="revoke: rotate key, re-grant everyone else">×</button></span>`
  ).join('') || `<span class="msg">nobody yet — this scope is published but dark</span>`
  const unshared = knownContacts.filter(p => !s.grantees.includes(p)).length
  return `
    <div class="sect2">shared with ${s.grantees.length ? `(${s.grantees.length})` : ''}</div>
    <div class="chips">${chips}</div>
    <div class="actions">
      <input class="share-pub" list="contactlist" placeholder="add by name, npub1…, or hex">
      <button class="share">Share</button>
      ${unshared > 1 ? `<button class="shareall">Share with all (${unshared})</button>` : ''}
      <span class="msg share-msg"></span>
    </div>`
}

function mineScopeHtml(s, i) {
  return `<div class="scopesec" data-i="${i}">
    <div class="head" style="justify-content:space-between">
      <div class="name">${esc(s.scopeName)}</div>
      <div class="msg" style="display:flex;align-items:center;gap:10px">${s.draft
        ? '<span class="badge draft-badge">draft — not yet published</span>'
        : `v${s.generation} · <span style="font-family:var(--mono)">${esc(s.scopeId)}</span>`}
        <button class="delscope icon" title="delete this scope">${TRASH_SVG}</button></div>
    </div>
    ${s.lost ? '<div class="stale">⚠ data set not found on these relays — Publish restores it</div>' : ''}
    <div class="frows">${editorRows(s.fields).map(frowHtml).join('')}</div>
    <div class="actions">
      <button class="addfield">+ field</button>
      <button class="primary publish">Publish</button>
      <span class="msg publish-msg"></span>
    </div>
    ${shareBlock(s)}
  </div>`
}

const SCOPE_ORDER = ['Basic', 'Personal', 'Work']
const orderKey = (s) => {
  const i = SCOPE_ORDER.indexOf(s.scopeName)
  return i === -1 ? SCOPE_ORDER.length : i
}

function renderMine() {
  const onCard = new Set(myScopes.map(s => s.scopeName))
  const addable = Object.keys(TEMPLATES).filter(t => t === 'Custom' || !onCard.has(t))
  const sorted = myScopes.map((s, i) => [s, i])
    .sort((a, b) => orderKey(a[0]) - orderKey(b[0]) || a[0].scopeName.localeCompare(b[0].scopeName))
  const myName = profiles.get(me)?.display_name || profiles.get(me)?.name
    || myScopes.map(s => s.fields.display_name).find(Boolean) || 'My card'
  const hue = parseInt(me.slice(0, 4), 16) % 360
  const initials = esc(String(myName).trim().split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase())

  $('mycard').innerHTML = `
    <datalist id="fieldnames">${Object.entries(FIELDS).map(([k, v]) =>
      `<option value="${k}">${v.hint}</option>`).join('')}</datalist>
    <datalist id="contactlist">${knownContacts.map(pk =>
      `<option value="${nip19.npubEncode(pk)}">${esc(contactName(pk))}</option>`).join('')}</datalist>
    <div class="onecard">
      <div class="head" style="padding:20px 24px 0">
        <div class="avatar" style="background:hsl(${hue} 45% 70%)">${initials}</div>
        <div class="who">
          <div class="name">${esc(myName)}</div>
          <div class="msg">the record only you maintain — grantees always see the current version</div>
        </div>
      </div>
      <div class="addbar">
        <span class="msg">add a scope:</span>
        ${addable.map(t => `<button class="tchip" data-t="${t}">+ ${t}</button>`).join('')}
        <span class="msg">— its own key, its own audience. Updates are free; unsharing rotates the key.</span>
      </div>
      ${sorted.map(([s, i]) => mineScopeHtml(s, i)).join('')}
    </div>`

  for (const chip of document.querySelectorAll('.tchip'))
    chip.onclick = () => newScope(chip.dataset.t)
  for (const sec of document.querySelectorAll('.scopesec')) {
    const i = Number(sec.dataset.i)
    sec.querySelector('.frows').addEventListener('input', (e) => {
      if (!e.target.classList.contains('ftype')) return
      const row = e.target.closest('.frow')
      row.querySelector('.ficon').textContent = FIELDS[e.target.value.trim()]?.icon || '·'
      row.querySelector('.fvalue').placeholder = FIELDS[e.target.value.trim()]?.hint ?? 'value'
    })
    sec.querySelector('.frows').addEventListener('click', (e) => {
      if (e.target.closest('.del')) e.target.closest('.frow').remove()
    })
    sec.querySelector('.addfield').onclick = () =>
      sec.querySelector('.frows').insertAdjacentHTML('beforeend', frowHtml())
    sec.querySelector('.delscope').onclick = () => deleteMine(i, sec)
    sec.querySelector('.publish').onclick = () => publishMine(i, sec)
    sec.querySelector('.share')?.addEventListener('click', () => shareFromInput(i, sec))
    sec.querySelector('.shareall')?.addEventListener('click', () => shareAll(i, sec))
    for (const un of sec.querySelectorAll('.unshare'))
      un.onclick = (e) => revokeShare(myScopes[i], e.target.closest('.chip').dataset.pub)
  }
}

async function deleteMine(i, sec) {
  const s = myScopes[i]
  if (s.draft) { myScopes.splice(i, 1); renderMine(); return }   // local only
  if (!confirm(`Delete "${s.scopeName}"?\n\nThe data set on relays is replaced by an empty tombstone under a key nobody holds, and a NIP-09 deletion request asks relays to drop even that. Your ${s.grantees.length} grantee(s) keep what they already saw and will see the scope as revoked.`)) return
  const msg = sec.querySelector('.publish-msg')
  msg.textContent = 'tombstoning…'
  try {
    await deleteScope(relay, signer, s)
    myScopes.splice(i, 1)
    await syncIndex()
    renderMine()
    if (bookState) render()
  } catch (err) { msg.textContent = err.message }
}

async function publishMine(i, sec) {
  const s = myScopes[i], msg = sec.querySelector('.publish-msg')
  msg.textContent = 'publishing…'
  try {
    s.fields = collectFields(sec)
    await publishScope(relay, signer, { ...s, payload: { name: s.scopeName, fields: s.fields } })
    const wasDraft = s.draft
    s.draft = false
    s.lost = false
    await syncIndex()
    if (wasDraft) { renderMine(); if (bookState) render(); return }
    msg.textContent = `live — ${s.grantees.length} grantee${s.grantees.length === 1 ? '' : 's'} see this on next fetch, no re-share needed`
  } catch (err) { msg.textContent = err.message }
}

async function shareFromInput(i, sec) {
  const msg = sec.querySelector('.share-msg')
  try {
    const pub = parsePub(sec.querySelector('.share-pub').value)
    msg.textContent = 'delivering grant…'
    await grantShare(myScopes[i], pub)
  } catch (err) {
    msg.textContent = err.message === 'not an npub'
      ? 'pick a contact from the list, or paste an npub' : err.message
  }
}

async function shareAll(i, sec) {
  const s = myScopes[i]
  const targets = knownContacts.filter(p => !s.grantees.includes(p))
  if (!confirm(`Grant "${s.scopeName}" to all ${targets.length} current contacts?\n\nOne-time: a grant is a deliberate act to a known key, so people who become contacts later are NOT auto-included.`)) return
  const msg = sec.querySelector('.share-msg')
  try {
    let n = 0
    for (const pub of targets) {
      msg.textContent = `granting… ${++n}/${targets.length}`
      await grant(relay, signer, pub, { ...s, relayHint: RELAYS[0] })
      if (!s.grantees.includes(pub)) s.grantees.push(pub)
    }
    await syncIndex()
    renderMine()
    if (bookState) render()
  } catch (err) { msg.textContent = err.message }
}

function newScope(template) {
  let name = template
  if (template === 'Custom') {
    name = (prompt('Scope name (grantees will see it):') ?? '').trim()
    if (!name) return
  }
  // A draft: local only. Nothing touches the relays until first Publish.
  myScopes.push({
    scopeId: 's' + crypto.getRandomValues(new Uint32Array(1))[0].toString(36),
    scopeName: name,
    generation: 1, scopeKey: newScopeKey(), grantees: [], publisher: me, draft: true,
    fields: Object.fromEntries(TEMPLATES[template].map(([f, label]) =>
      [f, label ? [{ value: '', label }] : ''])),
  })
  renderMine()
}

// ------------------------------------------------------------------ address book

function fieldsHtml(fields) {
  return Object.entries(fields).filter(([k]) => k !== 'display_name').map(([k, v]) =>
    (Array.isArray(v) ? v : [v]).map(item => {
      const value = item && typeof item === 'object' ? item.value : item
      const label = item && typeof item === 'object' ? item.label : ''
      return `<div class="field"><span class="ficon">${FIELDS[k]?.icon ?? '·'}</span>` +
        `<span class="fval">${esc(value)}</span>` +
        (label ? `<span class="flabel">${esc(label)}</span>` : '') + `</div>`
    }).join('')
  ).join('')
}

function scopeHtml(s) {
  const name = esc(s.scopeName || s.scopeId)
  if (s.status === 'ok')
    return `<div class="scope"><div class="sname"><span>${name}</span><span class="gen">v${s.generation}</span></div>${fieldsHtml(s.data.fields ?? {})}</div>`
  if (s.status === 'stale')
    return `<div class="scope"><div class="sname"><span>${name}</span></div><div class="stale">⚠ key rotated — access to updates revoked. Show last-known data greyed out.</div></div>`
  return `<div class="scope"><div class="sname"><span>${name}</span></div><div class="stale">data set not found on these relays</div></div>`
}

// Contact-axis sharing: your published scopes as toggle chips on each card.
// Filled chip = they hold the grant (× revokes); ghost chip = one click to grant.
function outboundHtml(pubkey) {
  const published = myScopes.filter(s => !s.draft)
  if (!published.length) return ''
  const chips = published.map(s => s.grantees.includes(pubkey)
    ? `<span class="chip shared" data-scope="${s.scopeId}" data-pub="${pubkey}">${esc(s.scopeName)}<button class="unshare" title="stop sharing (rotates key)">×</button></span>`
    : `<button class="suggest grant" data-scope="${s.scopeId}" data-pub="${pubkey}">+ ${esc(s.scopeName)}</button>`
  ).join('')
  return `<div class="sect2">you share with them</div><div class="chips outbound">${chips}</div>`
}

function card({ pubkey, isFollow, isFollower, scopes }) {
  const profile = profiles.get(pubkey)
  const shared = scopes.find(s => s.status === 'ok')
  const name = profile?.display_name || profile?.name
    || shared?.data?.fields?.display_name || nip19.npubEncode(pubkey).slice(0, 12) + '…'
  const initials = esc(name.trim().split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase())
  const hue = parseInt(pubkey.slice(0, 4), 16) % 360
  const npub = nip19.npubEncode(pubkey)
  const ok = scopes.filter(s => s.status === 'ok').length
  const stale = scopes.length - ok
  const iShare = myScopes.filter(s => !s.draft && s.grantees.includes(pubkey)).length
  const ghosted = iShare > 0 && ok === 0
  const badges = [
    ok ? `<span class="badge shares">shares ${ok} scope${ok > 1 ? 's' : ''} with you</span>` : '',
    stale ? `<span class="badge revoked">${stale} revoked</span>` : '',
    ghosted ? `<span class="badge ghost-badge">shares nothing back</span>` : '',
    isFollow ? `<span class="badge">following</span>` : '',
    isFollower ? `<span class="badge follows-you">follows you</span>` : '',
  ].join('')
  const rank = { ok: 0, stale: 1, missing: 2 }
  const inbound = scopes.length
    ? scopes.slice().sort((a, b) => rank[a.status] - rank[b.status]).map(scopeHtml).join('')
    : `<div class="nothing">nothing shared with you — their record, their call</div>`
  return `<div class="card${ghosted ? ' ghosted' : ''}">
    <div class="head">
      <div class="avatar" style="background:hsl(${hue} 45% 70%)">${initials}</div>
      <div class="who">
        <div class="name">${esc(name)}</div>
        <div class="npub" title="click to copy" data-npub="${npub}">${npub}</div>
      </div>
    </div>
    <div class="badges">${badges}</div>
    ${inbound}
    ${outboundHtml(pubkey)}
  </div>`
}

function render() {
  const { follows, followers, sharedBy } = bookState
  if (!knownContacts.length) {
    $('status').textContent = ''
    $('book').innerHTML = `<div class="empty" style="grid-column:1/-1">Nobody here yet.
      This key follows no one, has no followers, and holds no grants on these relays.<br>
      Run <code>npm run seed</code> and sign in with the printed nsec for a populated demo.</div>`
    return
  }
  const contacts = knownContacts.map(pubkey => ({
    pubkey,
    isFollow: follows.has(pubkey),
    isFollower: followers.has(pubkey),
    scopes: sharedBy.get(pubkey) ?? [],
    out: myScopes.filter(s => !s.draft && s.grantees.includes(pubkey)).length,
  }))
  // mutual/inbound sharers first, then outbound-only (ghosted), then the rest
  contacts.sort((a, b) =>
    (b.scopes.filter(s => s.status === 'ok').length - a.scopes.filter(s => s.status === 'ok').length)
    || (b.out - a.out) || (b.isFollow - a.isFollow))
  const sharers = contacts.filter(c => c.scopes.length).length
  const sharing = contacts.filter(c => c.out).length
  $('status').textContent =
    `${contacts.length} contacts — ${sharers} sharing with you, you're sharing with ${sharing}, ` +
    `${follows.size} followed, ${followers.size} following you. ` +
    `Shared data is dereferenced live: nothing below is a stored copy.`
  $('book').innerHTML = contacts.map(card).join('')
  for (const el of document.querySelectorAll('.npub'))
    el.onclick = () => navigator.clipboard.writeText(el.dataset.npub)
  const byId = (id) => myScopes.find(s => s.scopeId === id)
  for (const b of document.querySelectorAll('#book .grant'))
    b.onclick = () => { b.textContent = 'granting…'; grantShare(byId(b.dataset.scope), b.dataset.pub) }
  for (const un of document.querySelectorAll('#book .chip.shared .unshare'))
    un.onclick = (e) => {
      const c = e.target.closest('.chip')
      revokeShare(byId(c.dataset.scope), c.dataset.pub)
    }
}
