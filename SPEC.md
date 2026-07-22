# NIP-XX

## Permissioned Private Data Sharing (Scoped Data Grants)

`draft` `optional`

This NIP defines a permission-based model for sharing private, structured personal data (e.g. contact details) between nostr keyholders. Each user maintains one or more encrypted, authoritative **Scoped Data Sets** on relays. Access is granted per-recipient by privately delivering a **Data Grant** containing the symmetric key for a scope. Relays store only ciphertext and never learn the contents of a data set or the identities of grantees.

The design goals are:

- **Self-sovereign data**: the publisher holds the only authoritative copy; recipients dereference it rather than storing snapshots.
- **Live updates**: when the publisher updates a data set, all current grantees see the new version on next fetch, with no re-sharing step.
- **Scoped disclosure**: different recipients can be granted different subsets (scopes) of the publisher's data.
- **Private grant graph**: relays and third parties cannot determine who has granted access to whom.
- **Revocability of future access**: a publisher can rotate a scope key to cut off future updates to any grantee (historical plaintext already decrypted by a grantee is, unavoidably, retained by them).

This NIP builds on [NIP-44](44.md) (encrypted payloads) and [NIP-59](59.md) (gift wrap). It defines no new relay behavior; conforming relays require only standard NIP-01 support for addressable events.

## Definitions

- **Publisher**: the keyholder who owns and maintains a data set.
- **Grantee**: a keyholder who has been granted access to one or more of the publisher's scopes.
- **Scope**: a named subset of the publisher's data (e.g. `basic`, `personal`, `business`), encrypted under its own key.
- **Scope key**: a random 32-byte symmetric key under which a scope's data set is encrypted.
- **Grant**: the private delivery of a scope key (plus a pointer to the data set) from publisher to grantee.

## Event Kinds

| kind    | description                          | encryption                          |
| ------- | ------------------------------------ | ----------------------------------- |
| `30440` | Scoped Data Set (addressable)        | symmetric, under scope key          |
| `440`   | Data Grant (unsigned rumor)          | NIP-59 seal + gift wrap             |
| `441`   | Grant Revocation notice (rumor)      | NIP-59 seal + gift wrap (optional)  |
| `10440` | Grant Index (replaceable, self-use)  | NIP-44 to self                      |

Kind numbers are placeholders pending assignment.

## Scoped Data Set (`kind:30440`)

An addressable event holding one scope's data as ciphertext. The `d` tag identifies the scope.

```json
{
  "kind": 30440,
  "pubkey": "<publisher-pubkey>",
  "tags": [
    ["d", "<scope-id>"],
    ["v", "<scope-key-generation>"],
    ["u", "<content-seq>"]
  ],
  "content": "<symmetric-nip44-ciphertext>",
  ...
}
```

- `d`: an opaque scope identifier. Publishers SHOULD use short opaque strings (e.g. random 8-char ids) rather than semantic names like `family`, since `d` tags are visible to relays and semantic names leak information about the publisher's disclosure structure. The human-readable scope name belongs inside the encrypted payload or the publisher's Grant Index.
- `v`: the scope's **rotation generation** — an integer, incremented each time the scope key is rotated (and only then; content updates do not change it). This lets grantees detect that their key is stale without attempting decryption.
- `u`: the scope's **content sequence** — a strictly increasing integer, bumped on **every** publish of the scope (content updates *and* rotations), independent of `v`. `u` MUST be strictly greater than the `u` of any prior `kind:30440` for the same `(pubkey, d)`. Because it is a signed tag it is visible to relays without decryption, so a client can recognize a served copy as older than one it has already seen (see "Freshness and rollback detection").

### Payload encryption

The `content` is produced using the NIP-44 v2 payload format, with the 32-byte scope key used directly as the `conversation_key` (no ECDH step). This reuses NIP-44's authenticated encryption, versioning, and padding scheme — the padding is important, as it reduces leakage of data-set size to relays.

### Payload schema

The decrypted payload is a JSON object:

```json
{
  "name": "Personal",
  "updated_at": 1751904000,
  "fields": {
    "display_name": "James",
    "tel": [{"value": "+1...", "label": "mobile"}],
    "email": [{"value": "james@example.com", "label": "personal"}],
    "adr": [{"value": "...", "label": "home"}],
    "note": "..."
  }
}
```

Field names SHOULD follow vCard 4.0 (RFC 6350) property names in lowercase where an equivalent exists (`tel`, `email`, `adr`, `url`, `bday`, `org`, `title`), so that clients can interoperate with existing contact ecosystems. Arbitrary additional fields MAY be included; clients MUST ignore fields they do not understand.

As with all addressable events, publishing a new `kind:30440` with the same `d` tag replaces the previous one. This is the mechanism that makes grants "live": grantees always dereference the current event.

### Freshness and rollback detection

The two counters have distinct jobs: `v` is the **rotation generation**, bumped only when the scope key rotates; `u` is the **content sequence**, bumped on every publish. A rotation therefore bumps both; a content update bumps only `u`.

Replacement makes grants live, but a grantee talking to a single withholding relay could otherwise be pinned to an older, validly-signed event with no signal that a newer one exists. The `u` tag makes such rollback *detectable*:

- Grantees SHOULD fetch a scope from at least two relays (the publisher's NIP-65 write relays, plus any grant relay hints) and accept the event with the highest `(u, created_at)`, compared lexicographically. The signed `u` outranks `created_at`, which is self-asserted and may be skewed or fuzzed.
- Grantees SHOULD persist a per-scope high-water mark `(v, u)`, advanced from each accepted event, and MUST NOT downgrade to an event whose `(v, u)` is lexicographically lower than the stored mark. A lower value is a rollback signal: the client SHOULD warn and/or retry other relays rather than display the served copy as current. An event carrying no `u` tag compares as `u = 0` (so a pre-`u` copy served after a sequenced one is flagged too).
- The mark is keyed by scope identity `(publisher-pubkey, d)`: if the scope's `d` changes (see metadata hardening, when present), the high-water mark resets with the new scope identity.

Detection is the guarantee, not prevention: a relay can still withhold the newer event, and a grantee that has never seen the newer sequence — on any relay or in its mark — gets no signal (see Security 7).

## Data Grant (`kind:440`)

A grant delivers a scope key to a grantee. It MUST be an **unsigned rumor**, sealed (`kind:13`) and gift-wrapped (`kind:1059`) to the grantee exactly as specified in NIP-59, so that relays observe only an ephemeral pubkey delivering an opaque payload to the grantee. Publishers SHOULD also gift-wrap a copy to themselves for recoverability, following the NIP-17 convention.

The rumor:

```json
{
  "kind": 440,
  "pubkey": "<publisher-pubkey>",
  "created_at": 1751904000,
  "tags": [
    ["a", "30440:<publisher-pubkey>:<scope-id>", "<relay-hint>"],
    ["v", "<scope-key-generation>"],
    ["expiration", "<unix-timestamp>"]
  ],
  "content": "{\"scope_key\":\"<base64-32-bytes>\",\"scope_name\":\"Personal\"}"
}
```

- `a`: address of the data set this key decrypts. One or more relay hints SHOULD be included, since the grantee may share no relays with the publisher.
- `v`: the key generation this grant corresponds to.
- `expiration` (optional): a NIP-40 style timestamp after which the grantee SHOULD treat the grant as lapsed and clients SHOULD stop displaying the data. This is advisory — it is enforced by honest clients, not cryptography.
- `content`: JSON carrying the scope key and optional human-readable metadata.

Because the rumor is unsigned, a leaked grant is deniable; the grantee nevertheless authenticates it via the seal, per NIP-59.

### Grant authentication

The authenticated author of a grant is the `pubkey` of its NIP-59 **seal** (`kind:13`), recovered during unwrapping. Clients MUST compare this author to the publisher pubkey encoded in the grant's `a` tag (`30440:<publisher-pubkey>:<scope-id>`).

- If they are **equal**, the grant is a first-party grant.
- If they **differ**, the grant is a *re-wrapped* grant: some grantee has re-delivered a scope key it holds. A re-wrapped grant is cryptographically indistinguishable from key exfiltration. Clients MUST NOT present a re-wrapped grant as a first-party grant. Clients SHOULD reject re-wrapped grants by default; a client MAY accept one only under an explicit, deployment-defined delegation policy, and MUST surface the distinct author.

This is the grant-side counterpart of the data-set signer check (see Security 6). It is enforced by honest clients, not by cryptography: a grantee who holds a scope key can always share it out of band, where no client mediates. What the check guarantees is narrower and real — a conforming client never mistakes re-delivered key material for the publisher's own grant. Sanctioned onward delegation is instead performed with **derived scopes** — a sub-issuer publishing, and granting, its *own* `kind:30440` — for which author and `a`-tag publisher agree by construction (see [FUTURE.md](FUTURE.md), "Delegation chains").

### Grant requests

A prospective contact MAY request access by sending an ordinary NIP-17 direct message, or clients MAY implement a dedicated request flow out of band (QR code, link). This NIP deliberately does not standardize a request event: the grant decision is a human decision, and existing DM rails are sufficient to carry it.

## Updates, rotation, and revocation

**Updating data.** The publisher re-encrypts the payload under the existing scope key and republishes `kind:30440` with a bumped `u` (same `v`). No per-grantee action is required. Grantees SHOULD refetch data sets they hold grants for opportunistically (on app open, before displaying a contact, or on a periodic schedule).

**Revoking a grantee.** The publisher:

1. Generates a new scope key; increments `v`.
2. Republishes the `kind:30440` event encrypted under the new key (bumping `u`, as on every publish).
3. Issues fresh `kind:440` grants (new `v`) to all *remaining* grantees.
4. MAY send a `kind:441` revocation notice to the revoked party (gift-wrapped), containing the `a` tag of the affected scope, so their client can gracefully mark the contact data as no longer maintained. Publishers who prefer silent revocation simply skip this.

A revoked grantee retains any plaintext previously decrypted but can no longer read updates. Clients holding a grant whose `v` no longer matches the current data set event, and which have not received a fresh grant, SHOULD display the last-known data as stale/unmaintained rather than deleting it.

Key rotation cost is O(remaining grantees) per rotation. Publishers with large grantee sets SHOULD structure scopes so that broad, low-sensitivity data (rarely revoked) is separated from narrow, high-sensitivity data (small grantee count, cheap to rotate).

**Deleting a scope.** Replacement of an addressable event destroys the prior ciphertext on conforming relays, so deletion is a special case of rotation: the publisher SHOULD publish a final `kind:30440` replacement (a *tombstone*) with an empty payload, an incremented `v`, and a freshly generated key that is granted to no one, and MAY additionally publish a [NIP-09](09.md) deletion request (`kind:5` with the `a` tag of the scope) asking relays to drop the tombstone as well. Grantees observe generation supersession and treat the scope exactly as a revocation; previously decrypted plaintext is unaffected (see Security 2). The publisher then removes the scope from their Grant Index.

**Discovering new grants.** Grants arrive in the same `kind:1059` inbox as NIP-17 direct messages, and the inner kind is encrypted: a grantee cannot ask a relay for "grant wraps only". This indistinguishability is an intended property of NIP-59 — the grant graph is exactly what it protects — so the discovery cost cannot be filtered away server-side, only bounded. To bound it, grantees SHOULD treat the Grant Index (`kind:10440`) `received` list as the authoritative warm cache for the address book, and scan raw `kind:1059` wraps only incrementally — with a `since` filter anchored to a persisted checkpoint (the highest wrap `created_at` already processed) — to discover *new* grants. A full wrap re-scan is required only on cold recovery from the private key alone, when no Grant Index is found.

An incremental scan is subject to two correctness rules, both consequences of NIP-59's timestamp randomization (wrap `created_at` is canonically backdated by up to two days):

- The `since` filter MUST reach back at least the full randomization window (two days) behind the checkpoint. A wrap delivered *after* a scan may carry a `created_at` up to two days *older* than everything that scan saw; `since = checkpoint` silently loses such grants.
- Consecutive scans therefore overlap, and clients MUST deduplicate wraps by event id across scans, processing each wrap at most once. Trial-unwrapping a wrap is idempotent, so a forgotten id costs only a repeated decrypt, never a wrong result — the id set is a cost bound, not a safety mechanism, and MAY be pruned to the trailing two-day window.

The checkpoint and the id set together form the *inbox cursor*. A persisted cursor MUST NOT get ahead of the cache it summarizes: persist it in the same write as (or after) the `received` entries whose processing it records, since a cursor that outruns its cache hides grants behind an already-advanced checkpoint. The Grant Index is the natural home for both (see below) — one replaceable event updates cache and cursor atomically, and cold recovery stays "fetch one event".

## Grant Index (`kind:10440`)

To make grants recoverable across clients with only the user's private key, both publishers and grantees SHOULD maintain a replaceable Grant Index event whose `content` is NIP-44 encrypted to their own key (conversation key derived from their own keypair, as in NIP-51 private items):

```json
{
  "issued": [
    {"scope": "<scope-id>", "scope_name": "Personal", "v": 3, "u": 12,
     "key": "<base64>", "grantees": ["<pubkey>", "..."]}
  ],
  "received": [
    {"a": "30440:<pubkey>:<scope-id>", "v": 2, "u": 9, "key": "<base64>",
     "petname": "alice", "relays": ["wss://..."]}
  ],
  "inbox": {"since": 1751904000, "ids": ["<wrap-event-id>", "..."]}
}
```

For the publisher, `issued` is the authoritative record needed to perform rotations. For the grantee, `received` is effectively the private address book: a list of dereferenceable, self-updating contact cards. This event contains all key material and MUST never be published unencrypted.

`u` is optional in both lists. In `issued` it records the last content sequence the publisher emitted for the scope, so the next publish — from any device or session — can use a strictly greater value. In `received` it is the grantee's persisted high-water mark (see "Freshness and rollback detection"). An absent `u` means unknown: accept the newest visible event, as pre-`u` clients do.

`inbox` is optional: the grantee's inbox cursor (see "Discovering new grants"). `since` is the highest `kind:1059` `created_at` already processed; `ids` are the wrap ids already processed within the trailing two-day randomization window (grants *and* other wraps — a DM trial-unwrapped once need never be trial-unwrapped again; older ids MAY be pruned). Writers that do not maintain a cursor omit the member, and a writer unaware of it may drop it when rewriting the index; either way readers finding no cursor fall back to a full wrap scan, so the degradation is safe — slower, never lossy.

## Interaction with existing NIPs

- **NIP-02**: the public follow list and this NIP's private grant layer are independent and complementary. Following someone does not imply a grant in either direction.
- **NIP-51**: a grantee MAY additionally organize granted contacts using private list items; the Grant Index is distinct because it must carry key material.
- **NIP-65**: grantees SHOULD use the publisher's relay list metadata, plus grant relay hints, to locate `kind:30440` events.
- **NIP-05**: publishers MAY include their NIP-05 identifier inside a scope payload; it plays no role in the grant mechanism itself.
- **MLS-based group messaging** (NIP-EE / Marmot) solves a different problem: end-to-end encrypted *conversation streams* with forward secrecy and group evolution. This NIP addresses authoritative, addressable *data records* with live dereference and revocation-by-rotation; the two are orthogonal and complementary.

## Security and privacy considerations

1. **No forward secrecy within a scope generation.** Compromise of a scope key exposes the current payload and all payloads published under that generation. Rotation bounds the damage window. High-sensitivity fields warrant their own scope.
2. **Grantees retain decrypted plaintext.** Revocation controls future access only. This matches physical-world disclosure semantics and MUST be communicated honestly by clients ("stop sharing updates," not "un-share").
3. **Publisher metadata.** The existence, count, `d` tags, update timing, and (padded) size of a publisher's `kind:30440` events are visible to relays. Opaque `d` tags and NIP-44 padding mitigate but do not eliminate this. Publishers MAY additionally publish decoy updates.
4. **Grant graph privacy.** Gift wrapping hides publisher↔grantee links from relays. Traffic analysis by a relay observing both the wrap delivery and a subsequent fetch of a specific `kind:30440` address could correlate; grantees SHOULD fetch via their normal read relays and MAY delay first fetch by a random interval.
5. **Key loss.** Loss of the user's private key forfeits the Grant Index and therefore all issued and received grants. This NIP inherits nostr's key-management model; deployments serious about mainstream contact use cases should pair it with NIP-46 remote signing and/or social recovery schemes, which are out of scope here.
6. **Malicious data set replacement.** Only the publisher can sign a replacement `kind:30440`; grantees MUST verify the event signature and that its pubkey matches the `a` tag before decrypting.
7. **Relay withholding.** A relay can serve a stale `kind:30440` (rollback) or withhold it entirely. The signed `u` tag plus the persisted `(v, u)` high-water mark make rollback detectable without decryption, and multi-relay fanout makes it survivable whenever any queried relay carries the newer event (see "Freshness and rollback detection"); the `updated_at` field inside the payload corroborates after decryption. Detection has a limit: a grantee whose every relay withholds the newer event — and whose mark never advanced past the old one — sees no signal. Withholding, like erasure, cannot be prevented by protocol.

## Rationale

- **Symmetric scope keys rather than per-grantee encryption of the payload** make the data set O(1) in grantee count and make updates free, at the cost of rotation-on-revoke. For contact data — low churn in revocations, potentially high churn in field values — this is the right trade.
- **Reusing the NIP-44 payload format with a raw key** avoids introducing a second encryption construction into the ecosystem.
- **Unsigned gift-wrapped grants** follow NIP-17's deniability and metadata-privacy rationale; the grant graph is precisely the information this NIP exists to protect.
- **No new relay features** keeps the barrier to deployment at zero: this NIP is implementable today by clients alone against existing relays.
