// nipxx (Go) — NIP-XX Permissioned Private Data Sharing (Scoped Data Grants).
// Second, independent implementation of ../SPEC.md, over go-nostr. Interop
// counterpart to the JS reference lib (../nipxx.mjs); the two share nothing
// but the wire format.
//
//	go run . publish    -sk <hex> -scope <id> -gen <n> -seq <n> -key <b64> -payload <json>
//	go run . grant      -sk <hex> -to <pubhex> -scope <id> -gen <n> -key <b64> -name <name>
//	go run . book       -sk <hex>                 # grantee address book → JSON
//	go run . index-save -sk <hex>                 # fold received grants (+ inbox cursor) into kind-10440
//	go run . index-book -sk <hex>                 # address book from the index: warm cache, then
//	                                              # incremental wrap scan when it carries an inbox cursor
//
// All commands accept -relays wss://a,wss://b (defaults below).
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/nbd-wtf/go-nostr/nip59"
)

const (
	kindDataSet    = 30440
	kindGrant      = 440
	kindGrantIndex = 10440
)

var defaultRelays = "wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net"

// ---------------------------------------------------------------- transport

// seqOf reads the signed content sequence (the `u` tag, SPEC "Freshness and
// rollback detection"); 0 when absent.
func seqOf(ev *nostr.Event) int {
	if t := ev.Tags.GetFirst([]string{"u"}); t != nil && len(*t) > 1 {
		n, _ := strconv.Atoi((*t)[1])
		return n
	}
	return 0
}

func query(pool *nostr.SimplePool, urls []string, f nostr.Filter) []*nostr.Event {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	seen := map[string]bool{}
	var out []*nostr.Event
	for ie := range pool.FetchMany(ctx, urls, f) {
		if !seen[ie.ID] {
			seen[ie.ID] = true
			out = append(out, ie.Event)
		}
	}
	// Multi-relay fanout, freshest first: the signed `u` outranks created_at
	// (self-asserted, possibly skewed), so a relay serving a rolled-back data
	// set cannot shadow a newer sequence seen on another relay. Events with
	// no `u` tag (every non-30440 kind) compare as 0 and keep pure
	// created_at ordering — same comparator as the JS lib's byFreshness.
	// The final tiebreak is NIP-01's replacement tiebreak (lowest id
	// survives a created_at tie): a reader merging relays that have not yet
	// converged on a same-v rotation collision picks exactly the event the
	// relays will retain (SPEC "Concurrent publisher devices").
	sort.Slice(out, func(i, j int) bool {
		if ui, uj := seqOf(out[i]), seqOf(out[j]); ui != uj {
			return ui > uj
		}
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func publish(pool *nostr.SimplePool, urls []string, ev nostr.Event) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	acks := 0
	for r := range pool.PublishMany(ctx, urls, ev) {
		if r.Error == nil {
			acks++
		}
	}
	if acks == 0 {
		fatal("no relay accepted kind %d", ev.Kind)
	}
	fmt.Printf(`{"acks":%d,"of":%d}`+"\n", acks, len(urls))
	return acks
}

// ---------------------------------------------------------------- crypto

// NIP-44 v2 payload format with the raw 32-byte scope key used directly as
// the conversation key (no ECDH step) — same construction as the JS lib.
func symEncrypt(v any, key [32]byte) string {
	b, _ := json.Marshal(v)
	ct, err := nip44.Encrypt(string(b), key)
	if err != nil {
		fatal("encrypt: %s", err)
	}
	return ct
}

func keyFromB64(s string) [32]byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		fatal("scope key must be base64 of 32 bytes")
	}
	var k [32]byte
	copy(k[:], b)
	return k
}

// NIP-44 to self, as in NIP-51 private items — for the Grant Index.
func selfKey(sk string) [32]byte {
	pub, _ := nostr.GetPublicKey(sk)
	ck, err := nip44.GenerateConversationKey(pub, sk)
	if err != nil {
		fatal("self key: %s", err)
	}
	return ck
}

// ---------------------------------------------------------------- publisher

func cmdPublish(pool *nostr.SimplePool, urls []string, fs *flag.FlagSet, sk string) {
	scope := fs.Lookup("scope").Value.String()
	gen := fs.Lookup("gen").Value.String()
	key := keyFromB64(fs.Lookup("key").Value.String())
	var payload map[string]any
	if err := json.Unmarshal([]byte(fs.Lookup("payload").Value.String()), &payload); err != nil {
		fatal("payload must be JSON: %s", err)
	}
	payload["updated_at"] = time.Now().Unix()
	// `u` — the content sequence — bumps on every publish of the scope
	// (content update or rotation), independent of `v`; the CLI is stateless,
	// so the caller carries and passes the next value.
	ev := nostr.Event{
		Kind:      kindDataSet,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"d", scope}, {"v", gen}, {"u", fs.Lookup("seq").Value.String()}},
		Content:   symEncrypt(payload, key),
	}
	if err := ev.Sign(sk); err != nil {
		fatal("sign: %s", err)
	}
	publish(pool, urls, ev)
}

func cmdGrant(pool *nostr.SimplePool, urls []string, fs *flag.FlagSet, sk string) {
	pub, _ := nostr.GetPublicKey(sk)
	to := fs.Lookup("to").Value.String()
	content, _ := json.Marshal(map[string]string{
		"scope_key":  fs.Lookup("key").Value.String(),
		"scope_name": fs.Lookup("name").Value.String(),
	})
	// The grant is an unsigned rumor, sealed and gift-wrapped per NIP-59:
	// the relay sees only an ephemeral pubkey delivering a blob to the grantee.
	rumor := nostr.Event{
		PubKey:    pub,
		Kind:      kindGrant,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"a", fmt.Sprintf("%d:%s:%s", kindDataSet, pub, fs.Lookup("scope").Value.String()), ""},
			{"v", fs.Lookup("gen").Value.String()},
		},
		Content: string(content),
	}
	sealKey, err := nip44.GenerateConversationKey(to, sk)
	if err != nil {
		fatal("conversation key: %s", err)
	}
	wrap, err := nip59.GiftWrap(rumor, to,
		func(pt string) (string, error) { return nip44.Encrypt(pt, sealKey) },
		func(ev *nostr.Event) error { return ev.Sign(sk) },
		nil)
	if err != nil {
		fatal("gift wrap: %s", err)
	}
	publish(pool, urls, wrap)
}

// ---------------------------------------------------------------- grantee

type grantRec struct {
	Publisher string `json:"publisher"`
	ScopeID   string `json:"scopeId"`
	ScopeName string `json:"scopeName,omitempty"`
	// Authenticated grant author — the NIP-59 seal pubkey, as recovered by
	// GiftUnwrap. Differs from Publisher (the a-tag's data-set owner) when a
	// grantee re-wrapped a scope key it holds; see SPEC "Grant
	// authentication". Empty on records rebuilt from the Grant Index, where
	// the original wrap (and thus its seal) is no longer in hand.
	Author     string `json:"author,omitempty"`
	Generation int    `json:"generation"`
	// IssuedAt is the grant rumor's created_at — honest publisher time (the
	// rumor is never fuzzed; only seal and wrap timestamps are). Among
	// grants of equal (publisher, scope, generation) the latest issued wins
	// (see latestGrants): a P3 reconciling re-grant carries the same v as
	// the losing grant it repairs and supersedes it by this field. Zero on
	// records rebuilt from the Grant Index.
	IssuedAt nostr.Timestamp `json:"issuedAt,omitempty"`
	key      [32]byte
}

type bookEntry struct {
	grantRec
	Status string `json:"status"`
	// Seq is the fetched event's content sequence (`u` tag) — the
	// relay-visible freshness signal the caller persists as its per-scope
	// high-water mark. 0 (omitted) when the event predates the `u` tag.
	Seq  int             `json:"seq,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// inboxCursor is the grantee's persisted inbox cursor — the Grant Index
// `inbox` member (SPEC "Discovering new grants"). Since is the highest
// kind-1059 created_at already processed; Ids the wrap ids (grants and
// DMs alike) already processed within the trailing randomization window.
type inboxCursor struct {
	Since nostr.Timestamp `json:"since"`
	Ids   []string        `json:"ids"`
}

// wrapOverlap is NIP-59's timestamp-randomization window (two days): wrap
// created_at is canonically backdated by up to this much, so a wrap
// delivered after a scan may be timestamped older than everything that
// scan saw. An incremental query must reach this far behind its checkpoint
// — since = checkpoint would silently lose such grants — and, scans thus
// overlapping, dedup by wrap id keeps the overlap from being unwrapped
// twice. Same constant as the JS lib's WRAP_OVERLAP.
const wrapOverlap = 2 * 24 * 60 * 60

// receiveGrants collects and unwraps grants addressed to this keyholder.
// cur == nil is the historical full scan — unavoidable on cold recovery,
// since grants share kind 1059 with NIP-17 DMs and the inner kind is
// encrypted (an intended NIP-59 property; relays cannot pre-filter). With
// a cursor the scan is incremental per the wrapOverlap rules above. The
// advanced cursor is returned for the caller to persist together with the
// grants it accounts for; its id set is pruned to the trailing window.
func receiveGrants(pool *nostr.SimplePool, urls []string, sk string, cur *inboxCursor) ([]grantRec, inboxCursor) {
	pub, _ := nostr.GetPublicKey(sk)
	decrypt := func(otherPub, ct string) (string, error) {
		ck, err := nip44.GenerateConversationKey(otherPub, sk)
		if err != nil {
			return "", err
		}
		return nip44.Decrypt(ct, ck)
	}
	f := nostr.Filter{Kinds: []int{1059}, Tags: nostr.TagMap{"p": []string{pub}}}
	known := map[string]bool{}
	next := inboxCursor{Ids: []string{}}
	if cur != nil {
		next.Since = cur.Since
		if s := cur.Since - wrapOverlap; s > 0 {
			f.Since = &s
		}
		for _, id := range cur.Ids {
			known[id] = true
		}
	}
	wraps := query(pool, urls, f)
	for _, ev := range wraps {
		if ev.CreatedAt > next.Since {
			next.Since = ev.CreatedAt
		}
	}
	var out []grantRec
	for _, ev := range wraps {
		if ev.CreatedAt >= next.Since-wrapOverlap {
			next.Ids = append(next.Ids, ev.ID) // reappears next scan: remember it
		}
		if known[ev.ID] {
			continue // overlap dedup: processed on a prior scan
		}
		rumor, err := nip59.GiftUnwrap(*ev, decrypt)
		if err != nil || rumor.Kind != kindGrant {
			continue
		}
		a := rumor.Tags.GetFirst([]string{"a"})
		v := rumor.Tags.GetFirst([]string{"v"})
		if a == nil || len(*a) < 2 {
			continue
		}
		parts := strings.Split((*a)[1], ":")
		if len(parts) != 3 {
			continue
		}
		var c struct {
			ScopeKey  string `json:"scope_key"`
			ScopeName string `json:"scope_name"`
		}
		if json.Unmarshal([]byte(rumor.Content), &c) != nil {
			continue
		}
		gen := 0
		if v != nil && len(*v) > 1 {
			gen, _ = strconv.Atoi((*v)[1])
		}
		out = append(out, grantRec{
			Publisher: parts[1], ScopeID: parts[2], ScopeName: c.ScopeName,
			Author:     rumor.PubKey, // seal pubkey — GiftUnwrap authenticates it
			IssuedAt:   rumor.CreatedAt,
			Generation: gen, key: keyFromB64(c.ScopeKey),
		})
	}
	return out, next
}

// Keep only the newest grant per (publisher, scope) — key rotations supersede.
// Re-wrapped grants (authenticated author ≠ a-tag publisher) are dropped, per
// SPEC "Grant authentication": this reader implements the default-reject
// policy. Records rebuilt from the Grant Index carry no author and pass —
// accepting them was the user's earlier, deliberate decision. Among grants
// of EQUAL generation — legitimate after a P3 collision repair, whose
// reconciling re-grant reuses the colliding v — the latest issued wins
// (SPEC "Concurrent publisher devices"); index cache records (IssuedAt 0)
// thus yield to any later first-party re-grant at the same generation.
func latestGrants(grants []grantRec) []grantRec {
	best := map[string]grantRec{}
	for _, g := range grants {
		if g.Author != "" && g.Author != g.Publisher {
			continue // re-wrapped: not the publisher's own grant
		}
		k := g.Publisher + ":" + g.ScopeID
		if cur, ok := best[k]; !ok || g.Generation > cur.Generation ||
			(g.Generation == cur.Generation && g.IssuedAt > cur.IssuedAt) {
			best[k] = g
		}
	}
	out := make([]grantRec, 0, len(best))
	for _, g := range best {
		out = append(out, g)
	}
	return out
}

// Dereference a grant: fetch the current data set, verify its signature,
// compare generations, decrypt. Stale = the key was rotated past this grant.
func fetchScope(pool *nostr.SimplePool, urls []string, g grantRec) bookEntry {
	entry := bookEntry{grantRec: g, Status: "missing"}
	events := query(pool, urls, nostr.Filter{
		Kinds: []int{kindDataSet}, Authors: []string{g.Publisher},
		Tags: nostr.TagMap{"d": []string{g.ScopeID}},
	})
	if len(events) == 0 {
		return entry
	}
	ev := events[0]
	if ok, _ := ev.CheckSignature(); !ok {
		return entry
	}
	gen := 0
	if v := ev.Tags.GetFirst([]string{"v"}); v != nil && len(*v) > 1 {
		gen, _ = strconv.Atoi((*v)[1])
	}
	entry.Seq = seqOf(ev) // relay-visible content sequence, see bookEntry
	entry.Status = "stale"
	if gen > g.Generation {
		return entry
	}
	if pt, err := nip44.Decrypt(ev.Content, g.key); err == nil {
		entry.Status, entry.Data = "ok", json.RawMessage(pt)
	}
	return entry // MAC failure → stale (wrong, rotated key)
}

func cmdBook(pool *nostr.SimplePool, urls []string, sk string) {
	grants, _ := receiveGrants(pool, urls, sk, nil) // stateless CLI: full scan
	var book []bookEntry
	for _, g := range latestGrants(grants) {
		book = append(book, fetchScope(pool, urls, g))
	}
	printJSON(book)
}

// ---------------------------------------------------------------- grant index

type receivedEntry struct {
	A string `json:"a"`
	V int    `json:"v"`
	// U is the grantee's persisted per-scope high-water content sequence
	// (SPEC "Freshness and rollback detection"). Optional: 0 (omitted)
	// means unknown — accept the newest visible event, as pre-`u` clients do.
	U   int    `json:"u,omitempty"`
	Key string `json:"key,omitempty"`
	// Mtime and Deleted are P3 merge metadata (SPEC "Index merge rule"):
	// the entry's last-modification stamp and the tombstone marker that
	// keeps a merge from resurrecting a removed grant. This reader's whole
	// duty toward them is to read mtime-bearing indexes without breaking
	// and to skip tombstones (which carry no key); merging is a writer's
	// concern, and this CLI's index-save is a cold full rebuild.
	Mtime   int64    `json:"mtime,omitempty"`
	Deleted bool     `json:"deleted,omitempty"`
	Petname string   `json:"petname,omitempty"`
	Relays  []string `json:"relays"`
}

type grantIndex struct {
	Issued   []json.RawMessage `json:"issued"`
	Received []receivedEntry   `json:"received"`
	// Inbox is the optional inbox cursor (SPEC "Discovering new grants"),
	// written next to the received entries it accounts for — one replaceable
	// event updates cache and cursor atomically. Absent in indexes from
	// writers that do not maintain it; readers then fall back to a full scan.
	Inbox *inboxCursor `json:"inbox,omitempty"`
}

func cmdIndexSave(pool *nostr.SimplePool, urls []string, fs *flag.FlagSet, sk string) {
	grants, cursor := receiveGrants(pool, urls, sk, nil)
	index := grantIndex{Issued: []json.RawMessage{}, Received: []receivedEntry{}, Inbox: &cursor}
	for _, g := range latestGrants(grants) {
		index.Received = append(index.Received, receivedEntry{
			A: fmt.Sprintf("%d:%s:%s", kindDataSet, g.Publisher, g.ScopeID),
			V: g.Generation, Key: base64.StdEncoding.EncodeToString(g.key[:]),
			Petname: fs.Lookup("petname").Value.String(), Relays: []string{},
		})
	}
	ev := nostr.Event{
		Kind:      kindGrantIndex,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{},
		Content:   symEncrypt(index, selfKey(sk)),
	}
	if err := ev.Sign(sk); err != nil {
		fatal("sign: %s", err)
	}
	publish(pool, urls, ev)
}

// Recovery path: the address book from the nsec alone — load the index and
// warm-start per SPEC "Discovering new grants". The received entries are
// the cache (nothing is unwrapped for them); when the index carries an
// inbox cursor — written by either implementation — an incremental wrap
// scan bounded to the overlap window merges in whatever arrived since the
// snapshot. Cache entries come first, so on equal generation the user's
// earlier acceptance wins and a fresh discovery supersedes only by higher
// generation. No cursor → the book is served from the index alone.
func cmdIndexBook(pool *nostr.SimplePool, urls []string, sk string) {
	pub, _ := nostr.GetPublicKey(sk)
	events := query(pool, urls, nostr.Filter{Kinds: []int{kindGrantIndex}, Authors: []string{pub}})
	if len(events) == 0 {
		fatal("no grant index found")
	}
	pt, err := nip44.Decrypt(events[0].Content, selfKey(sk))
	if err != nil {
		fatal("decrypt index: %s", err)
	}
	var index grantIndex
	if err := json.Unmarshal([]byte(pt), &index); err != nil {
		fatal("parse index: %s", err)
	}
	var recs []grantRec
	for _, r := range index.Received {
		if r.Deleted {
			continue // tombstone (P3 merge rule): retained by writers, never dereferenced
		}
		parts := strings.Split(r.A, ":")
		if len(parts) != 3 {
			continue
		}
		recs = append(recs, grantRec{
			Publisher: parts[1], ScopeID: parts[2],
			Generation: r.V, key: keyFromB64(r.Key),
		})
	}
	if index.Inbox != nil {
		fresh, _ := receiveGrants(pool, urls, sk, index.Inbox)
		recs = append(recs, fresh...)
	}
	var book []bookEntry
	for _, g := range latestGrants(recs) {
		book = append(book, fetchScope(pool, urls, g))
	}
	printJSON(book)
}

// ---------------------------------------------------------------- main

func main() {
	if len(os.Args) < 2 {
		fatal("usage: nipxx <publish|grant|book|index-save|index-book> [flags]")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	sk := fs.String("sk", "", "secret key (hex)")
	relays := fs.String("relays", defaultRelays, "comma-separated relay urls")
	fs.String("scope", "", "scope id (opaque)")
	fs.String("gen", "1", "key generation")
	fs.String("seq", "1", "content sequence (u tag; strictly increasing per scope)")
	fs.String("key", "", "scope key (base64, 32 bytes)")
	fs.String("payload", "{}", "payload JSON")
	fs.String("to", "", "grantee pubkey (hex)")
	fs.String("name", "", "human-readable scope name")
	fs.String("petname", "", "petname for the publisher")
	fs.Parse(os.Args[2:])
	if *sk == "" {
		fatal("-sk is required")
	}
	urls := strings.Split(*relays, ",")
	pool := nostr.NewSimplePool(context.Background())

	switch os.Args[1] {
	case "publish":
		cmdPublish(pool, urls, fs, *sk)
	case "grant":
		cmdGrant(pool, urls, fs, *sk)
	case "book":
		cmdBook(pool, urls, *sk)
	case "index-save":
		cmdIndexSave(pool, urls, fs, *sk)
	case "index-book":
		cmdIndexBook(pool, urls, *sk)
	default:
		fatal("unknown command %q", os.Args[1])
	}
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
