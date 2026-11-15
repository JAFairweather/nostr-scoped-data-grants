# Capability Grants profile (`kind:440` / `kind:441`)

> **Status: PROPOSAL** for Frontier C7 (owner `waggle-dev`, reviewer `dennis`). Nothing here is an approved
> implementation until it is reviewed and merged. Where this profile says a consumer MUST behave in a way
> deployed code does not, the gap is listed in [§9](#9-conformance-gaps-in-deployed-code) and is fixed in that
> code by its own reviewed change; this document does not change any running system.
>
> Evidence: [`CAPABILITY-GRANTS-INVENTORY.md`](CAPABILITY-GRANTS-INVENTORY.md) (q-076) and the frozen vectors in
> [`fixtures/capability-grants-v1.json`](fixtures/capability-grants-v1.json) (`npm run smoke:fixtures`).

## 1. Scope and relation to [`SPEC.md`](SPEC.md)

Kinds `440` and `441` carry two wire profiles:

- **Scoped data grants** ([`SPEC.md`](SPEC.md)): `440` is an **unsigned rumor** that delivers a scope key and only ever
  travels inside a NIP-59 seal and gift wrap; `441` is an optional wrapped courtesy notice.
- **Capability grants** (this document): `440` is a **bare, signed** event published to relays that attests a scoped
  authority or a data-subject consent and carries no key material; `441` is a **signed** revocation of one such `440`.

The two never collide on the wire: a scoped-data `440` is never published unwrapped, and a capability `440` is never
wrapped. This profile keeps the deployed kinds rather than moving capability grants to new kinds, because every live
grant, broker, console and consent record already uses them and a move gains nothing a reader can observe.

### 1.1 Shape and classification

**Issuers MUST** produce exactly this shape:

| | Capability `440` | Capability `441` |
|---|---|---|
| Signed (`id` and valid BIP-340 `sig`) | required | required |
| Published bare on a relay (not inside a seal) | yes | yes |
| `["a", "30440:..."]` | absent | absent |
| `["da-cap", <cap>]` | exactly one | absent |
| `["da-scope", <hash>, <salt>]` | exactly one | absent |
| `["p", <grantee>]` | exactly one | optional (see §5) |
| `["e", <440-id>]` | absent | exactly one |
| `content` | `""` | `""` |

**Readers** that handle either profile MUST NOT treat one profile as the other, and:

- MUST confer nothing from a capability `440` that carries more than one `da-cap`, `da-scope` or `p` tag. Taking the
  first match is not conforming: two readers can then disagree about what the same signed event grants (one picks the
  first `da-cap`, another refuses the event). The same applies to more than one `e` on a capability `441`.
- SHOULD NOT act on an event carrying `["a", "30440:..."]` as a capability (it is shaped as a scoped-data grant).
- MAY ignore `content`; a non-empty `content` confers nothing extra.

An event that matches neither profile's shape confers nothing.

## 2. Capability `440`

```json
{
  "kind": 440,
  "pubkey": "<grantor>",
  "content": "",
  "tags": [
    ["p", "<64-hex grantee>"],
    ["da-scope", "<64-hex commitment>", "<32-hex salt>"],
    ["da-cap", "<cap>"],
    ["expiration", "<unix seconds>"]
  ]
}
```

- `pubkey` is the **grantor**. Which grantors a consumer accepts is the consumer's policy (for example an agent
  manifest's `grantors`, or a channel's grantor set); this profile does not define it.
- `p` is the **grantee**, 64 lowercase hex.
- `da-cap` names the capability, from the registry in §4. Cap-specific tags (§4) are REQUIRED where listed.
- `expiration` is OPTIONAL (NIP-40) and follows §6.

## 3. `da-scope`: the salted subject commitment

```text
da_scope = lowercase_hex(sha256(
  utf8("waggle/da-scope/v1") || 0x00 || utf8(subject) || hex_decode(salt)
))
```

- **Subject normalization (MUST, before hashing):** a Nostr pubkey is 64 lowercase hex (an `npub1...` is decoded
  first); a channel UUID is lowercase; any other subject (for example a community id) is its exact UTF-8 string. The
  subject each cap binds to is listed in §4.
- **Salt (issuers MUST):** 16 fresh random bytes per grant, written as 32 lowercase hex characters.
- **Salt (verifiers MUST):** reject a `da-scope` whose salt is not exactly 32 lowercase hex characters, and reject a
  commitment that is not 64 lowercase hex. A verifier MUST NOT silently decode a partial salt.
- **Match:** a reader that knows a candidate subject recomputes `da_scope` with the tag's salt and compares. Two grants
  for one subject are unlinkable to a reader who does not already know the subject.
- Reference vector (live grant `01a41ce2…`): subject `ebc6eec1…d2f3`, salt `5463a4e15781cbc705aedafa0423b08d`,
  `da_scope` `b6c00312269a4dab018e32de4102ffcdb57434d18c88d84619fd1030ee809911` (full values in the fixtures).

## 4. Capability registry

The registry is **closed**. Its machine-readable copy is [`capability-registry.json`](capability-registry.json);
`npm run smoke:registry` checks that every capability vector in the fixtures is registered, with the tags listed here,
and that the unknown-cap negative vector is not. A new capability is added by a reviewed change to this section and that
file, never by an issuer minting it first.

| `da-cap` | Status | `da-scope` subject | Grantee (`p`) | Required extra tags | Authority conferred |
|---|---|---|---|---|---|
| `admit` | active | channel UUID | member | — | seat in the channel roster; bridge return lane |
| `admit+read` | issuance disabled | channel UUID | member | — | `admit` plus history read once key delivery exists; consumers MAY accept, issuers MUST NOT mint until enabled |
| `task` | active | agent pubkey | operator | — | wake the agent and send it task instructions |
| `task+act` | active | agent pubkey | operator | — | `task` plus propose or approve gated actions |
| `task-relay` | active | agent pubkey | room bridge | — | carry room mentions from task-granted authors to the agent; never direct task authority |
| `shadow` | active | grantor's own pubkey | voice key, `p ≠ grantor` | — | non-transitive voice delegation of the grantor's live `task`/`task+act` and memory-write right |
| `mirror` | active | community id | bridge | `["tos", <64-hex sha256>]` | data-subject consent to mirror the signer's public notes into the community |
| `mention` | active | agent pubkey | peer, `p ≠ agent` | `["name", <handle>]`, handle `^[a-z0-9][a-z0-9._-]{0,31}$` (case-insensitive) | adds `@handle → p` to the agent's outbound mention allowlist |
| `onboard` | active | grantor's own pubkey | delegate, `p ≠ grantor` | `["policy", <terms version, 1–128 chars>]`, `["age", "confirmed"]` | submit seat-provisioning requests on the grantor's behalf |
| `memory-write` | dormant | grantor's own pubkey | writer seat | — | write to the grantor's memory, only where a consumer enables it explicitly |

### 4.1 Unknown capabilities (MUST)

- An **enforcer** (any consumer that grants authority from a `440`) MUST confer nothing for a `da-cap` it does not
  implement, including a registered one.
- An **issuer** MUST NOT mint an unregistered `da-cap`.
- An **audit or revocation surface** (a ledger that lists grants so their grantor can see and revoke them) MAY display
  an unknown `da-cap` under its raw value and MAY publish a `441` for it; displaying it MUST NOT imply authority.

## 5. Capability `441`: revocation

```json
{ "kind": 441, "pubkey": "<revoker>", "content": "", "tags": [["e", "<64-hex capability 440 id>"]] }
```

- A `441` revokes exactly the `440` its `e` tag names. An OPTIONAL `["p", <pubkey>]` lets relays route it to a
  subscriber filtering on `#p` (the `mirror` revocation addresses the bridge this way); it confers nothing.
- **Who may revoke (MUST):** a consumer MUST honor a `441` whose `pubkey` equals the target `440`'s `pubkey`. A consumer
  MAY also honor a `441` from any key it would accept as a grantor for that same grant, because a revocation only
  narrows authority. A consumer that does so SHOULD say so in its documentation, and any surface that **displays
  enforcement state** for that consumer SHOULD apply the same rule, so it does not show live a grant the enforcer
  treats as revoked.
- **Ordering (MUST):** a valid `441` revokes its target regardless of either event's `created_at`. The target id
  commits to the `440`'s `created_at`, so a `441` cannot precede its target; a consumer MUST NOT let a `441` with an
  earlier `created_at` than its target leave that target live. Consumers MUST collect revocations before deciding which
  grants are live (or otherwise produce the same result in any arrival order).
- A revocation is final for that `440`. Re-granting is a new `440`.

## 6. `expiration` (MUST)

- An enforcer MUST treat a capability `440` as not live once its NIP-40 `expiration` is at or before the current time.
- An `expiration` value that is not a base-10 integer number of seconds MUST be treated as already expired.
- A surface that displays grants SHOULD show an expired grant as expired, and MUST NOT show a malformed `expiration`
  as unexpired.

## 7. Verification order for an enforcer

1. Classify per §1.1; drop anything that is not a capability `440`/`441`.
2. Verify `id` and `sig`.
3. Check the grantor against the consumer's own grantor policy.
4. Check `da-cap` is one this consumer implements (§4.1) and its required extra tags (§4).
5. Check `da-scope` against the subject this consumer is deciding about (§3), with the salt rule.
6. Drop any `440` revoked by an honored `441` (§5), independent of order.
7. Drop any `440` that is expired or carries a malformed `expiration` (§6).

## 8. Fixtures

Each MUST above has a frozen vector in [`fixtures/capability-grants-v1.json`](fixtures/capability-grants-v1.json):

| Rule | Vectors |
|---|---|
| §1.1 classification | `scoped_data_rumor_vectors`, all `cap-440-*`, all `cap-441-*` |
| §3 salt and subject | `neg-440-bad-salt-nonhex`, `neg-440-npub-unnormalized-subject`, the live `da-scope` reference |
| §4 registry and cap tags | one `cap-440-*` per registered cap; `neg-440-self-shadow`, `neg-440-self-onboard` |
| §4.1 unknown cap | `neg-440-unknown-cap` |
| §5 who may revoke | `cap-441-revoke-task-same-author`, `cap-441-revoke-task-co-grantor`, `neg-441-outsider-author` |
| §5 ordering | `cap-441-revoke-task-backdated`, `cap-441-revoke-onboard-backdated` |
| §6 expiration | `cap-440-task-act-expiring`, `neg-440-expired`, `neg-440-malformed-expiration` |
| §7 signature | `neg-440-tampered-sig` |

## 9. Conformance gaps in deployed code

From the inventory's audited commits. Each is a follow-up for that code's owner, through its own review; listed here so
the profile and the code can be reconciled, not to claim they already agree.

| Rule | Deployed behavior that does not conform | Where |
|---|---|---|
| §1.1 single tags | Takes the **first** matching `p` / `da-cap` / `da-scope` tag instead of refusing an event with duplicates | `nvoy/mcp/tools/admission.mjs` (`tag()`, used by `foldGrantsWith` and `foldMemoryGrantsWith`), `nvoy/mcp/tools/onboard_delegate.mjs`, `nvoy/console/capgrants.mjs`, `waggle/src/bridge.mjs` (`processGrantEvent`), `waggle/src/consent.mjs`. `nave.pub/deploy/relay/write-policy.py` conforms (`only_tag`, one `da-scope`). |
| §1.1 `a` tag | Does not check for `["a", "30440:..."]` before acting on a capability `440` | the same nvoy and waggle readers; `nvoy/console/capgrants.mjs` conforms (classifies an `a`-tagged `440` as a data grant) |
| §5 ordering | **Backdated `441` leaves its `task`/`task+act`/`task-relay`/`shadow`/`mention` target live** (sorts by `created_at` and deletes only grants already seen). A revocation can silently fail to take. | `nvoy/mcp/tools/admission.mjs` `foldGrantsWith` |
| §3 salt | Non-hex salt is silently truncated by `Buffer.from(…, 'hex')` instead of rejected | `nvoy/mcp/tools/grant_fold.mjs` |
| §3 salt | Accepts `""` or any even-length hex salt | `waggle/src/scope_hash.mjs`, `waggle/console/scope-hash.mjs` |
| §6 expiration | Malformed `expiration` read as unexpired | `nvoy/mcp/src/capabilities.ts`, `nact/lib/actions.mjs` |
| §6 expiration | `expiration` not checked | `waggle/src/bridge.mjs` (`admit`), `waggle/src/consent.mjs` (`mirror`), `nvoy/console/capgrants.mjs` (display) |
| §5 display | Console pre-filters to same-author revocations while the broker honors co-grantors, so the console can show live a grant the broker treats as revoked | `waggle/console/hive-list.mjs` |
| §4 registry | Five divergent vocabulary copies (6, 6, 7, 8 caps); none lists all ten | `nave.pub/components/nave-cap.mjs`, `nact/lib/actions.mjs`, `nvoy/lib/nave-cap.mjs`, `waggle/console/capability-vocabulary.mjs`, `nvoy/mcp/src/capabilities.ts` |

## 10. Not in this proposal

- v3 caveats (expiry and attenuation on a capability grant, verified offline in JS and Go) build on this profile and
  follow as a separate change.
- Kind assignment: both profiles share placeholder kinds, as [`SPEC.md`](SPEC.md) notes.
