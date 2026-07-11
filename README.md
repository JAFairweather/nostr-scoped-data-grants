# NIP-XX: Scoped Data Grants

**Permissioned private data sharing on nostr** — a draft NIP plus two
independent reference implementations.

The core inversion: **nobody maintains contact data about anyone else.**
Each person keeps one encrypted, authoritative record of their own data on
relays and grants scoped access to specific keyholders. The "address book"
is an emergent view — a set of capabilities (pointer + decryption right)
that always dereference to current data. N self-maintained records instead
of N² rotting copies.

The spec is [SPEC.md](SPEC.md). Relays store only ciphertext and never learn
who granted access to whom.

## Status

- **Spec**: complete draft, including live update, key-rotation revocation,
  scope deletion, and the recoverable Grant Index.
- **Two independent implementations**: a JavaScript reference library
  ([`nipxx.mjs`](nipxx.mjs), isomorphic Node/browser) and a Go CLI
  ([`go/main.go`](go/main.go), built on go-nostr). They share nothing but
  the spec.
- **Interop verified on public relays**: each implementation decrypts the
  other's scopes via the other's grants, detects the other's key rotations,
  and recovers the address book from the other's Grant Index
  (`npm run interop`, 5 assertions, live).
- **Zero relay changes**: everything runs today on stock relays
  (verified against relay.damus.io, nos.lol, relay.primal.net). Only plain
  NIP-01 addressable-event semantics are required.
- Kinds `30440` / `440` / `441` / `10440` — unassigned in the NIPs registry
  at the time of writing.

## Quick start

```
npm install
npm run demo          # narrated protocol walkthrough (in-memory relay)
npm run smoke:local   # 11 assertions, in-memory
npm run smoke         # same 11 assertions against real public relays
npm run interop       # 5 JS↔Go cross-implementation assertions (needs Go)
npm run seed          # throwaway demo graph on live relays → prints a login key
```

## Applications built on NIP-DA

Four independent apps run on this protocol. Each lives in its own repo, ships
as a pure client (no server, no build step), and vendors the reference lib.

- **[Nontact](https://github.com/JAFairweather/nontact)** — the no-maintenance
  address book: nobody maintains contact data about anyone else.
  → [live](https://jafairweather.github.io/nontact/)
- **[Nvelope](https://github.com/JAFairweather/nvelope)** — live folders, real
  revocation (encrypted document sharing).
  → [live](https://jafairweather.github.io/nvelope/app/)
- **[Notegate](https://github.com/JAFairweather/notegate)** — serverless secure
  tip intake.
  → [live](https://jafairweather.github.io/notegate/)
- **[Nvoy](https://github.com/JAFairweather/nvoy)** — scoped, revocable data
  delegation to AI agents (MCP server).
  → [live](https://jafairweather.github.io/nvoy/)

Run `npm run seed` here for a throwaway demo graph, then sign in to Nontact
with the printed key.

## Protocol summary

| kind    | event                          | encryption                     |
| ------- | ------------------------------ | ------------------------------ |
| `30440` | Scoped Data Set (addressable)  | NIP-44 v2 under a random 32-byte *scope key* (no ECDH) |
| `440`   | Data Grant (unsigned rumor)    | NIP-59 seal + gift wrap        |
| `441`   | Revocation notice (optional)   | NIP-59 seal + gift wrap        |
| `10440` | Grant Index (replaceable)      | NIP-44 to self                 |

- **Live update** = republish `30440` under the same key; every grantee sees
  it on next fetch.
- **Revocation** = rotate the scope key, bump `v`, republish, re-grant
  survivors. Revoked parties keep already-decrypted plaintext (stated
  honestly — that is physics) but are cut off from all future updates.
- **Deletion** = replacement *is* destruction for addressable events: a
  tombstone under a never-granted key destroys the ciphertext on conforming
  relays, plus an advisory NIP-09 request.
- **Recovery** = the Grant Index makes everything — issued and received —
  recoverable from the private key alone.

## Files

| file            | role |
|-----------------|------|
| `SPEC.md`       | the draft NIP (source of truth) |
| `nipxx.mjs`     | JS reference implementation (~200 lines, async, isomorphic) |
| `relay.mjs`     | ~45-line in-memory NIP-01 relay + adversarial observer view |
| `liverelay.mjs` | SimplePool adapter for real relays |
| `demo.mjs`      | narrated lifecycle demo |
| `smoke.mjs`     | 11-assertion test, `--local` or live |
| `go/main.go`    | second implementation: Go CLI over go-nostr |
| `interop.mjs`   | JS↔Go cross-implementation test, live relays |
| `seed.mjs`      | demo-graph seeder for Nontact |

## Design notes

- **Symmetric scope keys** make the data set O(1) in grantee count and make
  updates free; revocation costs one rotation plus re-grants to survivors.
  The right trade for contact data: low revocation churn, high value churn.
- **NIP-44 payload format with a raw key**: no new cryptography enters the
  ecosystem, and the padding scheme limits size leakage to relays.
- **Unsigned gift-wrapped grants** (NIP-17's rationale): deniable if leaked,
  authenticated via the seal, invisible to relays. The grant graph is
  precisely the information this NIP exists to protect.
- **Opaque `d` tags**: semantic scope names like `family` would leak the
  publisher's disclosure structure even with encrypted contents.
- **`v` generation counter**: grantees detect rotation without attempting
  (and failing) decryption.
- Payload field names follow vCard 4.0 (RFC 6350) lowercase, so clients
  interoperate with existing contact ecosystems.

## License

Public domain ([CC0 1.0](LICENSE)), as required for NIPs.
