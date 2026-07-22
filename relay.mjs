// relay.mjs — a ~40-line in-memory relay implementing just enough NIP-01:
// event storage, filter queries, and replacement semantics for addressable
// events. The protocol needs NOTHING more from a relay — which is the point.
// Swap this for a SimplePool against wss:// relays and the demo is unchanged.

import { matchFilter, verifyEvent } from 'nostr-tools'

const isAddressable = (kind) => kind >= 30000 && kind < 40000
const isReplaceable = (kind) => kind === 0 || kind === 3 || (kind >= 10000 && kind < 20000)
const dTag = (event) => event.tags.find(t => t[0] === 'd')?.[1] ?? ''

// NIP-01 replacement identity: kind+pubkey+d for addressable events,
// kind+pubkey for replaceable ones, none for regular events.
const replaceKey = (e) =>
  isAddressable(e.kind) ? `${e.kind}:${e.pubkey}:${dTag(e)}`
  : isReplaceable(e.kind) ? `${e.kind}:${e.pubkey}`
  : null

export class Relay {
  events = []

  publish(event) {
    if (!verifyEvent(event)) throw new Error('invalid signature')
    if (this.events.some(e => e.id === event.id)) return // relays store one copy per id
    const key = replaceKey(event)
    if (key) {
      // NIP-01 replacement, properly: the incumbent survives unless the
      // arriving event is strictly newer — greater created_at, or equal
      // created_at with the lexicographically LOWER id. Arrival order does
      // not matter, which is what makes P3's same-v rotation collision
      // deterministic: every relay, whatever order it saw the rivals in,
      // retains the same survivor (SPEC "Concurrent publisher devices").
      const cur = this.events.find(e => replaceKey(e) === key)
      if (cur && (cur.created_at > event.created_at
          || (cur.created_at === event.created_at && cur.id < event.id))) return
      this.events = this.events.filter(e => replaceKey(e) !== key)
    }
    this.events.push(event)
  }

  query(filter) {
    return this.events
      .filter(e => matchFilter(filter, e))
      .sort((a, b) => b.created_at - a.created_at)
  }

  /** What an adversarial relay operator actually learns. */
  observerView() {
    return this.events.map(e => ({
      kind: e.kind,
      pubkey: e.pubkey.slice(0, 8) + '…',
      d: dTag(e) || undefined,
      bytes: e.content.length,
      content_preview: e.content.slice(0, 40) + '…',
    }))
  }
}
