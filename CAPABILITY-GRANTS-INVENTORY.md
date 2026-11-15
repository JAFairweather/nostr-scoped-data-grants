# Capability Grants (`kind:440` / `kind:441`) — `da-cap` & Consumer Inventory

> **Status & Governance (`q-076` -> Frontier `C7`):** This document is an empirical code-and-fixture inventory across `nostr-scoped-data-grants`, `waggle`, `nvoy`, `nave.pub`, and `nact`. It freezes verifiable test vectors in [`fixtures/capability-grants-v1.json`](fixtures/capability-grants-v1.json) (`npm run smoke:fixtures`) and surfaces cross-consumer divergences as input to **Frontier C7** (normative capability-grant specification owned by `waggle-dev`, reviewed by `dennis`). It intentionally leaves [`SPEC.md`](SPEC.md) untouched.

## Audited Repository Commits

| Repository | Audited Commit | Notes |
| --- | --- | --- |
| `JAFairweather/nostr-scoped-data-grants` | `4f14f439b7b8b41f2c3a8b6f998e6791eb217f8c` | Base `main` for this inventory and fixture suite |
| `JAFairweather/waggle` | `ea0290cd0357a5dff939ab9746eda751c580ef0e` | Plus open PR `#746` (`c4ae443122183a93ca5917e3250c87406c769d07`) for console `onboard` issuance |
| `JAFairweather/nvoy` | `516d12b0a30369aa0eab43172e29620a3320f302` | Broker admission, mention directory, onboarding delegate, ledger & MCP capability tools |
| `JAFairweather/nave.pub` | `1217c4e81612ab7870dce33e6b73c488f23841ef` | Relay strfry `write-policy.py` and `<nave-cap>` badge web component |
| `JAFairweather/nact` | `292155009611139fe0bdd3efe7e27c0c0690a642` | NIP-46 action inbox / signer UI for capability `440`/`441` drafts |

---

## 1. Two Wire Profiles Sharing Event Kinds `440` and `441`

In the current codebase, event numbers `440` and `441` appear in two distinct wire profiles. Both `kind:440` profiles permit an optional NIP-40 `["expiration", "<unix-sec>"]` tag, but they share zero scope-binding, capability, or revocation target tags:

| Property | Profile A: Scoped Data Grant ([`SPEC.md`](SPEC.md)) | Profile B: Deployed Capability Grant (`waggle` / `nvoy` / `nave.pub` / `nact`) |
| --- | --- | --- |
| **Purpose** | Deliver a symmetric 32-byte NIP-44 `scope_key` decrypting an addressable `kind:30440` Scoped Data Set | Publicly attest or revoke a scoped authority or data-subject consent without key material |
| **Inner signature** | **Unsigned rumor** (`no id`, `no sig`; [`SPEC.md:107-115`](SPEC.md#L107-L115), [`SPEC.md:147`](SPEC.md#L147)) | **Bare BIP-340 Schnorr-signed Nostr event** (`id` + 64-byte `sig`) |
| **Transport** | NIP-59 `kind:13` seal + `kind:1059` gift wrap (never published bare on a relay) | Published directly to grant relays (`wss://relay.nave.pub`, `wss://relay.ditto.pub`, `wss://relay.primal.net`, `wss://nos.lol` per `nvoy/mcp/tools/grant_relays.mjs:3-8`) |
| **`kind:440` tags** | `["a", "30440:<pub>:<d>", "<relay-hint>"]`, `["v", "<gen>"]`, optional `["expiration", "<ts>"]` | `["p", "<64-hex-grantee>"]`, `["da-scope", "<64-hex-hash>", "<salt-hex>"]`, `["da-cap", "<cap>"]`, optional `["expiration", "<ts>"]`, plus cap-specific tags |
| **`kind:440` `content`** | JSON `{"scope_key":"<base64>","scope_name":"..."}` | Empty string `""` |
| **`kind:441` revocation** | Optional courtesy rumor (`["a", "30440:<pub>:<d>"]`); real revocation is key rotation (`v+1` on `30440`) | Authoritative signed revocation carrying `["e", "<64-hex-440-id>"]` (plus `["p", "<bridge-pubkey>"]` on `mint-consent.mjs` mirror revocations) |
| **`kind:440` classifier boundary** | Unsigned (`no id`, `no sig`), has `["a", "30440:..."]` + `["v", "<gen>"]`, lacks `da-cap` / `da-scope` | Signed (`id` + `sig`), lacks `["a", "30440:..."]`, carries `p` + `da-scope` + `da-cap` (`nvoy/console/capgrants.mjs:24-45`, `nvoy/mcp/src/capabilities.ts:85-89`) |
| **`kind:441` classifier boundary** | Unsigned (`no id`, `no sig`), has `["a", "30440:..."]`, lacks `e` | Signed (`id` + `sig`), lacks `["a", "30440:..."]`, carries `["e", "<64-hex-440-id>"]` (`p` is absent except on `mint-consent.mjs` `mirror` revocations for `#p`-filtered relay subscriptions) |

> **Related non-grant carrier:** `waggle/src/join_request.mjs:17,23,49` also uses `["da-cap", "<cap>"]` inside ephemeral **kind `27493`** join-request events (`REQUESTABLE_CAPS = ['admit', 'task', 'task+act', 'task-relay']`). Kind `27493` is an unprivileged request, never an active grant.

---

## 2. `da-scope` Salted Commitment Construction & Implementations

Capability `kind:440` events hide the scope identifier from casual relay scraping via a salted SHA-256 commitment:

```text
da_scope_hash = hex(sha256(
  utf8("waggle/da-scope/v1") || 0x00 || utf8(normalized_subject) || hex_decode(salt_hex)
))
```

- **Tag layout:** `["da-scope", "<64-lowercase-hex-hash>", "<salt-hex>"]`, using a fresh 16-byte (`32`-hex-char) random salt per grant so two grants for the same subject produce unlinkable tag values until a reader who already knows the candidate `subject` tests `scopeMatches(event, subject)`.
- **Subject normalization:** If `subject` is a Nostr pubkey given as `npub1...`, issuers normalize it to 64 lowercase hex characters before UTF-8 encoding (`waggle/src/scope_hash.mjs:44-56`); channel UUIDs are normalized to lowercase ASCII; community IDs (e.g., `mirrorConsentHiveId`) are hashed as exact UTF-8 strings. Note that hex pubkeys are hashed as **64 ASCII UTF-8 bytes**, whereas `salt_hex` is **hex-decoded to raw bytes** (`16` bytes for a 32-char hex salt).
- **Frozen live relay reference vector** (`waggle/tests/scope_hash.mjs:65-75`, live grant `01a41ce2d42a0a7c22e70342ea93bc5693180bfe11ec275c235afd0a3e13d80d`):
  - `subject`: `"ebc6eec1a7c36304c8093d2f60337045b60678e858fe3997eb9740215bfdd2f3"`
  - `salt_hex`: `"5463a4e15781cbc705aedafa0423b08d"`
  - `expected_hash`: `"b6c00312269a4dab018e32de4102ffcdb57434d18c88d84619fd1030ee809911"`

### `da-scope` Implementations Across Repositories

| Repository & File | Runtime | Salt Validation Rule |
| --- | --- | --- |
| `waggle/src/scope_hash.mjs:31-76` | Node (`node:crypto`) | Even-length hex `/^([0-9a-f]{2})+$/i` or `""`; `mintScopeTag` generates 16 random bytes (`32` hex chars) |
| `waggle/console/scope-hash.mjs:31-65` | Browser (`crypto.subtle`) | Even-length hex `/^([0-9a-f]{2})+$/i` or `""`; `mintScopeTag` generates 16 random bytes |
| `nvoy/mcp/tools/grant_fold.mjs:28-30,66-70` | Node (`node:crypto`) | `Buffer.from(saltHex \|\| '', 'hex')` (see Divergence #5: partial/silent non-hex truncation in Node) |
| `nvoy/console/task-authority-lib.mjs:6-20` | Browser (`crypto.subtle`) | Mint-only (`crypto.getRandomValues(new Uint8Array(16))`) |
| `nave.pub/deploy/relay/write-policy.py:224-228,266-267` | Python (`hashlib.sha256`) | Strictest: `re.fullmatch(r"[0-9a-f]{32}", salt)` (lowercase 32-hex only) |

---

## 3. Complete Inventory of `da-cap` Values in Source

Across all five repositories, exactly **10** `da-cap` string values appear in code:

| # | `da-cap` | Event `pubkey` (Signer) | `p` Tag (Grantee) | `da-scope` Subject Preimage | Extra Required / Optional Tags | Issuance Status | Summary of Authority / Effect |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `admit` | Channel grantor (`PUB.grantors`) | Admitted member / agent | Lowercase channel UUID (`PUB.inbox`) | Optional `["expiration", "<unix-sec>"]` | **Active** | Seats `p` in the channel roster and opens the Waggle bridge return lane so `p`'s outbound posts bridge back into the room |
| 2 | `admit+read` | Channel grantor (`PUB.grantors`) | Admitted member / agent | Lowercase channel UUID (`PUB.inbox`) | Optional `["expiration", "<unix-sec>"]` | **Disabled at issuance; accepted by bridge** | Intended admission + history read; accepted in `waggle/src/bridge.mjs:1199`, disabled in `waggle/console/capability-vocabulary.mjs:185-189` pending Concord key delivery / NIP-42 relay membership |
| 3 | `task` | Agent grantor (`manifest.grantors`) | Task sender / operator | 64-hex agent pubkey (`ME`) | Optional `["expiration", "<unix-sec>"]` | **Active** | Direct `nativeGrant`: authorizes `p` to wake and send task instructions to agent `ME` |
| 4 | `task+act` | Agent grantor (`manifest.grantors`) | Task sender / operator | 64-hex agent pubkey (`ME`) | Optional `["expiration", "<unix-sec>"]` | **Active** | Direct `nativeGrant` (preferred over `task` when both exist) + authority to propose/approve gated actions |
| 5 | `task-relay` | Agent grantor (`manifest.grantors`) | Waggle room bridge (`p`) | 64-hex agent pubkey (`ME`) | Optional `["expiration", "<unix-sec>"]` | **Active** | Channel carrier `relayGrant`: authorizes room bridge `p` to deliver room `@mention`s from task-granted authors to `ME` (never confers direct DM task authority) |
| 6 | `shadow` | Grantor `G` (`manifest.grantors` or memory owner) | Delegated voice key (`p !== G`) | Grantor `G`'s **own** 64-hex pubkey | Optional `["expiration", "<unix-sec>"]` | **Active (CLI-issued)** | Non-transitive voice delegation: `p` inherits `G`'s live `task` / `task+act` authority on brokers (`admission.mjs:92-98`, excluding `mentions` and DM `nativeGrant`) and `G`'s write right in `foldMemoryGrantsWith` |
| 7 | `mirror` | External Nostr participant (data subject) | Waggle bridge (`BRIDGE_PK`) | Community / hive ID (`PUB.mirrorConsentHiveId`) | Required `["tos", "<64-hex-sha256>"]` | **Active** | Opt-in data-subject consent permitting Waggle egress/bridge to mirror the signer's public Nostr notes into the named community |
| 8 | `mention` | Agent grantor (`manifest.grantors`) | Mentionable peer key (`p !== ME`) | 64-hex agent pubkey (`ME`) | Required `["name", "<handle>"]` (`/^[a-z0-9][a-z0-9._-]{0,31}$/i`), optional `expiration` | **Active** | Adds `@<handle> -> p` to agent `ME`'s outbound mention allowlist (`agent_post.mjs`, `agent_card.mjs`) |
| 9 | `onboard` | Hive owner (`grantor`) | Onboarding delegate (`p !== owner`) | Owner's **own** 64-hex pubkey | Required `["policy", "<terms-ver>"]` (non-empty, `<=128` chars) + `["age", "confirmed"]`, optional `expiration` | **Active** (`nvoy` + `nave.pub` main; `waggle#746` console UI) | Authorizes `p` to submit `kind:30078` (`d=nvoy:onboard:<req>`) seat-provisioning requests on `owner`'s behalf and pass `nave.pub` strfry write policy |
| 10 | `memory-write` | Memory owner (`DEFAULT_MEMORY_OWNER`) | Memory writer seat (`p`) | Memory owner's **own** 64-hex pubkey | Optional `["expiration", "<unix-sec>"]` | **Dormant / gated** | Implemented in `nvoy/mcp/tools/admission.mjs:9,152-155` (`foldMemoryGrantsWith`), gated behind `allowMemoryWrite = false` default; live Hive memory writes currently use manifest `may_remember` + `writers.json` |

---

## 4. Repository-by-Repository Issuer & Consumer Matrix

### 4.1 `waggle` (`ea0290cd0357a5dff939ab9746eda751c580ef0e` + PR `#746`)

| File & Lines | Role | `da-cap` Values Handled | Behavior Summary |
| --- | --- | --- | --- |
| `src/scope_hash.mjs:31-76` | Shared primitive | All | `scopeHash`, `mintScopeTag`, `scopeMatches`, `normalizePubkey` |
| `tools/grant.mjs:161-183` | CLI issuer | `admit`, `task`, `task+act`, `task-relay`, `shadow` | Mints signed `kind:440` (`shadow` hashes grantor's own pubkey and enforces `grantee !== author`) or `kind:441` (`--revoke <event-id>`) |
| `tools/propose-admission.mjs:62-68` | Action draft issuer | `admit` | Wraps an unsigned `kind:440` `admit` draft into NIP-46 `propose_event` for `nact` |
| `tools/mint-consent.mjs:75-106` | CLI issuer / revoker | `mirror` | Mints participant-signed `kind:440` (`mirror` + `tos`) or `kind:441` carrying both `["e", <440-id>]` and `["p", <bridge-pk>]` |
| `src/bridge.mjs:1135-1226` | Runtime consumer | `admit`, `admit+read` | `loadInitialGrants`, `subscribeGrants`, `processGrantEvent`: populates `grantSet` and opens return lane; revokes when `441.pubkey` is in `PUB.grantors` |
| `src/bridge.mjs:1228-1276,1316-1326` | Runtime consumer & prefill builder | `mirror` | `subscribeConsents` (`#p` + `#e` on accepted consent IDs), `processConsentEvent`, `buildConsentPrefill` |
| `src/consent.mjs:44-103` | Runtime consumer | `mirror` | `verifyConsent` + `readConsents`; enforces `p === bridgePubkey`, `scopeMatches(hiveId)`, `tos === expectedTosHash`, and strict `441.pubkey === 440.pubkey` |
| `src/nostr_egress.mjs:353-366` | Prefill issuer | `mirror` | Builds unsigned `kind:440` mirror consent prefill inside egress DMs |
| `src/join_request.mjs:17-55` | Ephemeral request | `admit`, `task`, `task+act`, `task-relay` | Validates kind `27493` join requests (`REQUESTABLE_CAPS`) |
| `tools/participant-init.mjs:176-185` & `tools/participant-state.mjs:92-120` | Provisioning / diagnostics | `admit`, `admit+read`, `task`, `task+act`, `task-relay` | Waits for `admit` `440` on relay during init; inspects live room/agent grants |
| `console/capability-vocabulary.mjs:52-215` | UI vocabulary | `admit`, `admit+read` (disabled), `task`, `task+act`, `task-relay`, `shadow` (grant-only badge), `mirror`, `mention` | Defines console labels, subject facets, and requestable/issuable flags |
| `console/hive-change.mjs:37-89,180-191` | Browser issuer / revoker | `admit`, `task`, `task+act`, `task-relay`, `mention` | `draftAuthority`, `draftPass`, `draftMention`, `draftRevoke`, `passesOf` (`441.pubkey === 440.pubkey`) |
| `console/hive-list.mjs:13,32-55` | Browser consumer | `admit`, `task`, `task+act`, `task-relay`, `shadow`, `mention` | Folds channel passes + vendored `nvoy-admission.mjs` agent authority for roster UI |
| `console/index.html:1350,1446`, `connect.html:497`, `add-agent-flow.mjs` | Browser issuers | `admit`, `task`, `task+act`, `task-relay` | Interactive grant signing and revocation flows |
| `console/hive-onboard.mjs:41-49` (PR `#746`) | Browser issuer | `onboard` | `draftOnboardGrant`: `da-cap="onboard"`, `da-scope(owner)`, `["policy", ver]`, `["age", "confirmed"]`, optional `expiration` |

### 4.2 `nvoy` (`516d12b0a30369aa0eab43172e29620a3320f302`)

| File & Lines | Role | `da-cap` Values Handled | Behavior Summary |
| --- | --- | --- | --- |
| `mcp/tools/grant_fold.mjs:12-77` | Shared primitive | Re-exports `admission.mjs` | `scopeHash`, `scopeMatches`, `grantRelays`, `readGrants` (`#p` + `#e` two-pass fetch) |
| `mcp/tools/admission.mjs:6-105` | Core broker consumer | `task`, `task+act`, `task-relay`, `shadow`, `mention` | `foldGrantsWith`, `nativeGrant`, `readGrants`: computes `{ senders, relays, mentions, grants }` for agent `ME` |
| `mcp/tools/admission.mjs:114-199` | Memory-grant consumer | `shadow`, `memory-write` | `foldMemoryGrantsWith`: folds owner self-authority + `shadow` voices (+ `memory-write` only if `allowMemoryWrite === true`) |
| `mcp/tools/attention.mjs:158-184`, `wake-watcher.mjs:127`, `status_snapshot.mjs:157`, `instance-broker.mjs:194-200` | Runtime enforcers | `task`, `task+act`, `task-relay`, `shadow`, `mention` | Enforces wake admission, channel relay authority, and NIP-46 action authority (`task+act`) |
| `mcp/tools/agent_post.mjs:63-88` & `agent_card.mjs:68-75` | Runtime consumers | `mention` | Builds outbound `@handle -> pubkey` map from folded `mentions` and advertises mentionable peers |
| `mcp/tools/onboard_delegate.mjs:47-100` -> `nvoy-onboard.mjs:72`, `onboard_request.mjs:115-128` | Onboarding consumer | `onboard` | `foldOnboardGrants` / `readOnboardGrants`: enforces `p !== owner`, `scopeMatches(owner)`, non-empty `policy <= 128`, `age === "confirmed"`, NIP-40 `expiration`, and `441.pubkey === owner` |
| `mcp/tools/nvoy-status.mjs:72-95` | CLI diagnostics | Any `da-cap` on `#p = agent` | Summarizes live vs revoked (`441`) grants targeting an agent |
| `mcp/src/capabilities.ts:22-171` (`app.ts:220`) | MCP consumer | Generic (labels 6 caps, passes through unknown `da-cap`) | `readHeldCapabilities`: lists capabilities where user is grantee (`#p`) or issuer (`authors`), folding `441` where `441.pubkey === 440.pubkey` |
| `console/capgrants.mjs:24-125` (`ledger.mjs`, `scope-facet.mjs`, `grantee-kind.mjs`) | Console ledger consumer & revoker | Generic (`classifyGrant` accepts any non-`30440` `440` with `da-cap`) | Displays issued capability grants and publishes `kind:441` revocations (`buildExternalRevocation`) |
| `console/task-authority-lib.mjs:22-51` | Browser issuer / revoker | `task`, `task+act`, `task-relay` | `buildGrantTemplate` & `buildRevokeTemplate` |
| `console/consent-request.mjs:53-65` & `consent-publish.mjs:12-20` | Browser issuer | `mirror` | Parses mirror consent deep-links and signs/publishes `kind:440` with `tos` |
| `lib/nave-cap.mjs:20-52` | UI badge component | `mirror`, `admit`, `admit+read`, `task-relay`, `task`, `task+act`, `shadow` | `<nave-cap>` custom element |

### 4.3 `nave.pub` (`1217c4e81612ab7870dce33e6b73c488f23841ef`)

| File & Lines | Role | `da-cap` Values Handled | Behavior Summary |
| --- | --- | --- | --- |
| `deploy/relay/write-policy.py:139-145,252-280,305-345,473-491` | Relay write-policy enforcer | `onboard` (enforced on `30078` `nvoy:onboard:*`); accepts signed `440`/`441` on relay | Verifies `onboard` grant (`p === writer`, `p !== owner`, 32-hex lowercase salt, `scopeMatches(owner)`, `age == "confirmed"`, `policy <= 128`, unexpired, unrevoked by `owner`) AND records a persistent local freeze fence on `kind:441` so replaying an older `440` cannot reopen onboarding |
| `components/nave-cap.mjs:18-50` | UI badge component | `mirror`, `admit`, `admit+read`, `task-relay`, `task`, `task+act` | `<nave-cap>` custom element (older 6-cap copy) |

### 4.4 `nact` (`292155009611139fe0bdd3efe7e27c0c0690a642`)

| File & Lines | Role | `da-cap` Values Handled | Behavior Summary |
| --- | --- | --- | --- |
| `lib/actions.mjs:24,110-168` | NIP-46 signer / action inbox | `admit`, `admit+read`, `task`, `task+act`, `task-relay`, `mirror` (vocabulary); generic `440`/`441` row rendering | Builds `kind:440` task grant proposals (`buildGrantEvents`) and renders pending/signed `440` grants and `441` revocations |

---

## 5. Five Cross-Consumer Divergences Surfaced for Frontier C7

Every divergence below has a corresponding frozen test vector in [`fixtures/capability-grants-v1.json`](fixtures/capability-grants-v1.json):

1. **Vocabulary / Registry Drift & Unknown-`da-cap` Disposition (`neg-440-unknown-cap`)**
   - **Registry drift across 5 copies:**
     - `nave.pub/components/nave-cap.mjs:18` & `nact/lib/actions.mjs:24`: 6 caps (`admit`, `admit+read`, `task`, `task+act`, `task-relay`, `mirror`).
     - `nvoy/lib/nave-cap.mjs:20`: 7 caps (adds `shadow`).
     - `waggle/console/capability-vocabulary.mjs:52-60`: 8 caps (adds `mention`; lacks `onboard` and `memory-write`).
     - `nvoy/mcp/src/capabilities.ts:22-29` (6 human labels) and `nvoy/console/capgrants.mjs:43` (5 human labels) fall back to raw `da-cap` strings for newer caps (`mention`, `onboard`, `shadow`).
   - **Per-consumer disposition on an unknown `da-cap` (`neg-440-unknown-cap`, `da-cap = "unknown-future-cap"`):**

     | Consumer Surface | Disposition on Unknown `da-cap` | Exact Source Citation |
     | --- | --- | --- |
     | `waggle` bridge room admission | **Ignore** (zero room/return-lane authority) | `waggle/src/bridge.mjs:1199` (`cap !== 'admit' && cap !== 'admit+read'`) |
     | `waggle` mirror consent verifier | **Reject** (`{ ok: false, reason: 'not a mirror capability' }`) | `waggle/src/consent.mjs:46` |
     | `nvoy` broker task/mention/shadow fold | **Ignore** (zero `senders`, `relays`, `mentions`, or `grants` entries) | `nvoy/mcp/tools/admission.mjs:76-85` (`foldGrantsWith`) |
     | `nvoy` memory grant fold | **Ignore** (zero writer authority) | `nvoy/mcp/tools/admission.mjs:150-156` (`foldMemoryGrantsWith`) |
     | `nvoy` onboarding delegate fold & `nave.pub` relay policy | **Ignore** for onboarding authority (`cap !== 'onboard'`) | `nvoy/mcp/tools/onboard_delegate.mjs:67`, `nave.pub/deploy/relay/write-policy.py:265` |
     | `waggle` CLI / join-request & `nact` proposal builders | **Reject** at construction; console marks `known: false, requestable: false` | `waggle/tools/grant.mjs:175`, `src/join_request.mjs:23`, `console/capability-vocabulary.mjs:160-175`, `nact/lib/actions.mjs:113` |
     | `nvoy` console universal ledger (`capgrants.mjs`) | **Display & allow `441` revocation** (`type: 'capability'`, `label: "Capability: <cap>"`) so delegators never lose visibility/revoke control over grants issued by newer apps | `nvoy/console/capgrants.mjs:21-45,98-106` |
     | `nvoy` MCP `readHeldCapabilities`, `nvoy-status`, `nact` `actionRows`, `<nave-cap>` | **Display** with raw `da-cap` fallback label (confers zero runtime authority) | `nvoy/mcp/src/capabilities.ts:85-89,105`, `mcp/tools/nvoy-status.mjs:80`, `nact/lib/actions.mjs:142-158`, `nvoy/lib/nave-cap.mjs:39` |

   - **C7 question:** Establish one canonical capability registry, preserve the intentional split between fail-closed runtime authority enforcers and app-agnostic audit/revocation ledgers, and settle the disposition of `admit+read` and `memory-write`.

2. **Revocation Signer Rule: Strict Same-Author (`441.pubkey === 440.pubkey`) vs Grantor-Pool (`441.pubkey in grantors`)**
   - *Vectors:* `cap-441-revoke-task-co-grantor` (plus negative control `neg-441-outsider-author`).
   - **Grantor-pool revokers:** `waggle/src/bridge.mjs:1151-1180` (`admit`) and `nvoy/mcp/tools/admission.mjs:68-72` (`foldGrantsWith` for `task`/`task+act`/`task-relay`/`shadow`/`mention`) allow *any* pubkey in `grantors` to revoke a `440` authored by *another* grantor in the same pool.
   - **Strict same-author revokers:** `waggle/console/hive-list.mjs:43,49`, `waggle/console/hive-change.mjs:186`, `waggle/src/consent.mjs:96`, `nvoy/mcp/tools/onboard_delegate.mjs:59,71`, `nvoy/mcp/src/capabilities.ts:127`, and `nave.pub/deploy/relay/write-policy.py:275` require `441.pubkey === 440.pubkey`. Because `waggle/console/hive-list.mjs` pre-filters revocations by `r.pubkey === g.pubkey` before calling `nvoy-admission`, the Waggle console UI can display a co-grantor-revoked grant as still active while the nvoy broker treats it as revoked.

3. **Backdated Revocation Ordering (`441.created_at < 440.created_at`)**
   - *Vectors:* `cap-441-revoke-task-backdated` (primary cross-consumer divergence control on `cap-440-task`) and `cap-441-revoke-onboard-backdated` (order-independent `onboard` control).
   - Because `kind:441` references a specific `kind:440` event ID (`["e", <440-id>]`) — which commits to `440.created_at` inside the SHA-256 preimage — a `441` cannot exist before its target `440` was constructed, even under clock skew.
   - **Timestamp-sorted consumer (`nvoy/mcp/tools/admission.mjs:67-85` `foldGrantsWith`):** accepts `cap-440-task` (`da-cap = "task"` in `TASK_CAPS`), sorts `440` and `441` events together by `created_at` ascending, and deletes from `live` when visiting a `441`. On `cap-441-revoke-task-backdated` (`441.created_at < 440.created_at`), `foldGrantsWith` processes the `441` before `cap-440-task` is inserted and **leaves `cap-440-task` live** in `senders`/`grants`.
   - **Order-independent consumers** (`waggle/src/bridge.mjs:1139-1153,1203`, `waggle/src/consent.mjs:82-97`, `waggle/console/hive-list.mjs:43-49`, `nvoy/mcp/tools/onboard_delegate.mjs:10-11,57-75`, `nvoy/mcp/tools/admission.mjs:142-169` `foldMemoryGrantsWith`, `nvoy/mcp/src/capabilities.ts:122-135`, `nvoy/console/capgrants.mjs:93-97`, `nave.pub/deploy/relay/write-policy.py:270-278`) collect all valid `441` target IDs first and **drop matching `440`s regardless of `created_at`** (exercised for `task` by `cap-441-revoke-task-backdated` and for `onboard` by `cap-441-revoke-onboard-backdated`; note that `admission.mjs:foldGrantsWith` ignores `onboard` regardless of `441`).

4. **NIP-40 `expiration` Tag Enforcement & Malformed Values**
   - *Vectors:* `cap-440-task-act-expiring`, `neg-440-expired`, `neg-440-malformed-expiration`.
   - **Fail-closed (enforced + non-digit string treated as expired):** `nvoy/mcp/tools/admission.mjs:31-37`, `nvoy/mcp/tools/onboard_delegate.mjs:30-34`, `waggle/console/hive-list.mjs:49`, `nave.pub/deploy/relay/write-policy.py:278`.
   - **Fail-open on non-numeric `expiration`:** `nvoy/mcp/src/capabilities.ts:137-142` and `nact/lib/actions.mjs:143,157` parse non-finite `Number(exp)` as `null` (unexpired).
   - **No `expiration` check:** `waggle/src/bridge.mjs:processGrantEvent`, `waggle/src/consent.mjs:verifyConsent`, and `nvoy/console/capgrants.mjs:toRow`.

5. **`da-scope` Salt Hex Validation Strictness**
   - *Vector:* `neg-440-bad-salt-nonhex`.
   - `nave.pub/deploy/relay/write-policy.py:225` requires `^[0-9a-f]{32}$` (16-byte lowercase hex).
   - `waggle/src/scope_hash.mjs:38` and `waggle/console/scope-hash.mjs:35` accept `""` or any even-length hex `/^([0-9a-f]{2})+$/i` and throw on non-hex characters.
   - `nvoy/mcp/tools/grant_fold.mjs:29` calls `Buffer.from(saltHex || '', 'hex')` without regex validation; in Node.js, `Buffer.from('zzzz...', 'hex')` silently stops at the first non-hex character pair and hashes `0` salt bytes instead of rejecting the tag.

---

## 6. Frozen Fixture Suite (`fixtures/capability-grants-v1.json`)

Run the offline verifier with:

```sh
npm run smoke:fixtures
```

[`smoke-capability-fixtures.mjs`](smoke-capability-fixtures.mjs) verifies with zero network access and zero stored private keys:

- **Live relay `da-scope` reference vector:** `01a41ce2...` -> `b6c00312...`.
- **2 [`SPEC.md`](SPEC.md) unsigned rumor vectors:** `440` Data Grant rumor and `441` courtesy revocation rumor (`scoped_data_rumor` profile).
- **10 BIP-340 signed `kind:440` capability grant vectors:** one for every `da-cap` value in code (`admit`, `admit+read`, `task`, `task+act`, `task-relay`, `shadow`, `mirror`, `mention`, `onboard`, `memory-write`), independently checking `getEventHash`, `@noble/curves/secp256k1` `schnorr.verify`, `nostr-tools` `verifyEvent`, `da-scope` preimage recomputation, and per-capability tag invariants.
- **5 BIP-340 signed `kind:441` capability revocation vectors:** standard same-author `task` revocation, `mirror` revocation with bridge `p` tag, backdated `task` `441` (`created_at < 440.created_at`, proving the `admission.mjs:foldGrantsWith` vs order-independent consumer divergence on a supported task grant), backdated `onboard` `441` (order-independent `onboard` revocation), and co-grantor `task` `441` (`pubkey !== 440.pubkey`).
- **9 negative control vectors:** unknown `da-cap` (`neg-440-unknown-cap`, proving fail-closed runtime rejection vs generic ledger display), outsider `441`, self-`shadow`, self-`onboard`, non-hex salt (`Buffer.from` truncation control), unnormalized `npub1...` subject, expired NIP-40 `440`, malformed NIP-40 `expiration`, and tampered BIP-340 signature.
