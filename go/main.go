// nipxx (Go) — NIP-XX Permissioned Private Data Sharing (Scoped Data Grants).
// Second, independent implementation of ../SPEC.md, over go-nostr. Interop
// counterpart to the JS reference lib (../nipxx.mjs); the two share nothing
// but the wire format.
//
//	go run . publish    -sk <hex> -scope <id> -gen <n> -key <b64> -payload <json>
//	go run . grant      -sk <hex> -to <pubhex> -scope <id> -gen <n> -key <b64> -name <name>
//	go run . book       -sk <hex>                 # grantee address book → JSON
//	go run . index-save -sk <hex>                 # fold received grants into kind-10440
//	go run . index-book -sk <hex>                 # address book from the index alone → JSON
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
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
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
	ev := nostr.Event{
		Kind:      kindDataSet,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"d", scope}, {"v", gen}},
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
	Publisher  string `json:"publisher"`
	ScopeID    string `json:"scopeId"`
	ScopeName  string `json:"scopeName,omitempty"`
	Generation int    `json:"generation"`
	key        [32]byte
}

type bookEntry struct {
	grantRec
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data,omitempty"`
}

func receiveGrants(pool *nostr.SimplePool, urls []string, sk string) []grantRec {
	pub, _ := nostr.GetPublicKey(sk)
	decrypt := func(otherPub, ct string) (string, error) {
		ck, err := nip44.GenerateConversationKey(otherPub, sk)
		if err != nil {
			return "", err
		}
		return nip44.Decrypt(ct, ck)
	}
	var out []grantRec
	for _, ev := range query(pool, urls, nostr.Filter{
		Kinds: []int{1059}, Tags: nostr.TagMap{"p": []string{pub}},
	}) {
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
			Generation: gen, key: keyFromB64(c.ScopeKey),
		})
	}
	return out
}

// Keep only the newest grant per (publisher, scope) — key rotations supersede.
func latestGrants(grants []grantRec) []grantRec {
	best := map[string]grantRec{}
	for _, g := range grants {
		k := g.Publisher + ":" + g.ScopeID
		if cur, ok := best[k]; !ok || g.Generation > cur.Generation {
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
	var book []bookEntry
	for _, g := range latestGrants(receiveGrants(pool, urls, sk)) {
		book = append(book, fetchScope(pool, urls, g))
	}
	printJSON(book)
}

// ---------------------------------------------------------------- grant index

type receivedEntry struct {
	A       string   `json:"a"`
	V       int      `json:"v"`
	Key     string   `json:"key"`
	Petname string   `json:"petname,omitempty"`
	Relays  []string `json:"relays"`
}

type grantIndex struct {
	Issued   []json.RawMessage `json:"issued"`
	Received []receivedEntry   `json:"received"`
}

func cmdIndexSave(pool *nostr.SimplePool, urls []string, fs *flag.FlagSet, sk string) {
	index := grantIndex{Issued: []json.RawMessage{}, Received: []receivedEntry{}}
	for _, g := range latestGrants(receiveGrants(pool, urls, sk)) {
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

// Recovery path: the address book from the nsec alone — load the index,
// dereference each received entry. No gift-wrap scan, no local state.
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
	var book []bookEntry
	for _, r := range index.Received {
		parts := strings.Split(r.A, ":")
		if len(parts) != 3 {
			continue
		}
		book = append(book, fetchScope(pool, urls, grantRec{
			Publisher: parts[1], ScopeID: parts[2],
			Generation: r.V, key: keyFromB64(r.Key),
		}))
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
