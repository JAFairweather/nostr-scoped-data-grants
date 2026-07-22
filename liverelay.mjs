// liverelay.mjs — the same publish/query interface as relay.mjs, backed by
// nostr-tools SimplePool against real public relays. The protocol code in
// nipxx.mjs is untouched; only the transport changes.

import { SimplePool, useWebSocketImplementation } from 'nostr-tools/pool'

// Node >= 21 ships a global WebSocket; older versions need the ws package.
if (typeof WebSocket === 'undefined') {
  const { default: WS } = await import('ws')
  useWebSocketImplementation(WS)
}

// Freshness order (SPEC "Freshness and rollback detection"): the signed
// content sequence `u` outranks created_at, which is self-asserted and may
// be skewed or fuzzed — so a relay serving a rolled-back data set cannot
// shadow a newer sequence seen on another relay. Events without a `u` tag
// (every non-30440 kind, pre-`u` data sets) compare as 0, leaving their
// ordering — newest created_at first — unchanged. The final tiebreak is
// NIP-01's replacement tiebreak (the lexicographically lowest id survives a
// created_at tie), so a client merging relays that have not yet converged
// on a P3 same-v rotation collision picks exactly the event the relays
// will retain — identical from every perspective, with no coordination
// (SPEC "Concurrent publisher devices").
const uOf = (e) => Number(e.tags.find(t => t[0] === 'u')?.[1] ?? 0)
const byFreshness = (a, b) => (uOf(b) - uOf(a)) || (b.created_at - a.created_at)
  || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)

export class LiveRelay {
  constructor(urls) {
    this.urls = urls
    this.pool = new SimplePool()
  }

  /** Publish to all relays; resolve when at least one relay ACKs.
   *  Some relays rate-limit by never replying, so each publish races an
   *  8s timeout — a silent relay counts as a rejection, not a hang. */
  async publish(event) {
    const timeout = () => new Promise((_, rej) =>
      setTimeout(() => rej(new Error('timeout: relay never replied')), 8000))
    const results = await Promise.allSettled(
      this.pool.publish(this.urls, event).map(p => Promise.race([p, timeout()])))
    const acks = results.filter(r => r.status === 'fulfilled').length
    const rejections = results
      .filter(r => r.status === 'rejected')
      .map(r => String(r.reason).slice(0, 60))
    if (acks === 0) throw new Error(`no relay accepted kind ${event.kind}: ${rejections.join(' | ')}`)
    return { acks, of: this.urls.length, rejections }
  }

  /** Multi-relay fanout: query all relays, merge (deduplicated by event
   *  id), freshest first — max (u, created_at). */
  async query(filter) {
    const events = await this.pool.querySync(this.urls, filter, { maxWait: 4000 })
    const seen = new Set()
    return events
      .filter(e => !seen.has(e.id) && seen.add(e.id))
      .sort(byFreshness)
  }

  close() { this.pool.close(this.urls) }
}

/** Wrap synchronous in-memory relay(s) in the same async interface. Several
 *  inners make a local multi-relay: publish fans out to all, query merges
 *  across all — the same id-dedupe and (u, created_at) preference as
 *  LiveRelay, so fanout freshness is testable deterministically. */
export class LocalRelay {
  constructor(...inners) { this.inners = inners }
  async publish(event) {
    for (const r of this.inners) r.publish(event)
    return { acks: this.inners.length, of: this.inners.length, rejections: [] }
  }
  async query(filter) {
    const seen = new Set()
    return this.inners.flatMap(r => r.query(filter))
      .filter(e => !seen.has(e.id) && seen.add(e.id))
      .sort(byFreshness)
  }
  close() {}
}
