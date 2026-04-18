package mullvadproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const relayJSON = `{
 "locations": {"se-got": {"city":"Gothenburg","country":"Sweden","latitude":0,"longitude":0}},
 "wireguard": {
   "ipv4_gateway":"10.64.0.1","ipv6_gateway":"fc00::1","port_ranges":[[51820,51820]],
   "relays":[{"active":true,"hostname":"se-got-wg-001","include_in_country":true,"ipv4_addr_in":"1.1.1.1","ipv6_addr_in":"::1","location":"se-got","public_key":"k","weight":100,"owned":true}]
 }
}`

func newTestCfg(t *testing.T, url string) MullvadConfig {
	t.Helper()
	dir := t.TempDir()
	return MullvadConfig{
		RelayURL:       url,
		DataFile:       filepath.Join(dir, "relays.json"),
		MetaFile:       filepath.Join(dir, "relays.meta.json"),
		ProxyPort:      1080,
		UpdateInterval: time.Hour,
	}
}

// newServer returns a server whose HEAD returns etag/lastMod and GET returns relayJSON,
// plus counters for HEAD and GET calls.
func newServer(etag, lastMod string) (*httptest.Server, *int, *int) {
	var headCount, getCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		if lastMod != "" {
			w.Header().Set("Last-Modified", lastMod)
		}
		switch r.Method {
		case http.MethodHead:
			headCount++
		case http.MethodGet:
			getCount++
			w.Write([]byte(relayJSON))
		}
	}))
	return srv, &headCount, &getCount
}

// Cold-start path: no in-memory Relays, no disk cache → must GET and parse.
// This is the first-ever-run scenario; a regression would leave Relays nil
// and every SelectProxies call failing.
func TestUpdate_FetchesWhenNoCache(t *testing.T) {
	Relays = nil
	srv, _, getCount := newServer(`"v1"`, time.Now().UTC().Format(time.RFC1123))
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)

	if err := update(cfg); err != nil {
		t.Fatal(err)
	}
	if *getCount != 1 {
		t.Fatalf("want 1 GET, got %d", *getCount)
	}
	if Relays == nil || len(Relays.Wireguard.Relays) != 1 {
		t.Fatal("relays not parsed")
	}
	if _, err := os.Stat(cfg.DataFile); err != nil {
		t.Fatal("data file not written")
	}
	Relays = nil
}

// Regression test for the bug fixed earlier: when Relays==nil but the disk
// cache is valid and the remote ETag matches, update must parse from disk
// instead of refetching. Counts GETs to prove no network fetch happens.
func TestUpdate_UsesDiskCacheWhenETagMatches(t *testing.T) {
	Relays = nil
	etag := `"v1"`
	srv, _, getCount := newServer(etag, "")
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)

	// Seed disk cache + meta with matching etag.
	if err := os.WriteFile(cfg.DataFile, []byte(relayJSON), 0644); err != nil {
		t.Fatal(err)
	}
	metaBytes, _ := json.Marshal(metadata{ETag: etag})
	if err := os.WriteFile(cfg.MetaFile, metaBytes, 0644); err != nil {
		t.Fatal(err)
	}

	if err := update(cfg); err != nil {
		t.Fatal(err)
	}
	if *getCount != 0 {
		t.Fatalf("want 0 GET (cache hit), got %d", *getCount)
	}
	if Relays == nil {
		t.Fatal("expected relays parsed from disk cache")
	}
	Relays = nil
}

// Steady-state tick: Relays already in memory, remote unchanged → no-op.
// Protects against wasted bandwidth and unnecessary disk writes on the
// hourly ticker when nothing has changed.
func TestUpdate_SkipsWhenRelaysLoadedAndETagMatches(t *testing.T) {
	Relays = makeRelays()
	etag := `"v2"`
	srv, _, getCount := newServer(etag, "")
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)
	metaBytes, _ := json.Marshal(metadata{ETag: etag})
	os.WriteFile(cfg.MetaFile, metaBytes, 0644)

	if err := update(cfg); err != nil {
		t.Fatal(err)
	}
	if *getCount != 0 {
		t.Fatalf("want 0 GET, got %d", *getCount)
	}
	Relays = nil
}

// ETag mismatch must trigger a refetch even when Relays is already loaded.
// Without this, the client would serve stale relay data indefinitely after
// Mullvad publishes a new list.
func TestUpdate_FetchesWhenETagChanged(t *testing.T) {
	Relays = makeRelays()
	srv, _, getCount := newServer(`"new"`, "")
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)
	metaBytes, _ := json.Marshal(metadata{ETag: `"old"`})
	os.WriteFile(cfg.MetaFile, metaBytes, 0644)

	if err := update(cfg); err != nil {
		t.Fatal(err)
	}
	if *getCount != 1 {
		t.Fatalf("want 1 GET, got %d", *getCount)
	}
	Relays = nil
}

// Non-2xx HEAD must surface as an error so StartUpdater can log it.
// Previously a 500 would pass the nil-err check and feed junk headers into
// the freshness comparison, potentially overwriting the cache with garbage.
func TestUpdate_ReturnsErrorOnHTTPFailure(t *testing.T) {
	Relays = nil
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)

	if err := update(cfg); err == nil {
		t.Fatal("expected error on 500")
	}
}

// loadMeta must degrade gracefully to a zero metadata{} when the file is
// absent — that's the signal update uses to force a first fetch. Returning
// an error instead would break the cold-start path.
func TestLoadMeta_MissingFileReturnsZero(t *testing.T) {
	cfg := newTestCfg(t, "http://unused")
	m := loadMeta(cfg)
	if m.ETag != "" || !m.LastModified.IsZero() {
		t.Fatalf("want zero metadata, got %+v", m)
	}
}

// parse must propagate JSON errors so update can fall back to a network
// fetch when the on-disk cache is corrupted (partial write, disk full, etc.)
// rather than silently leaving Relays nil.
func TestParse_InvalidJSONReturnsError(t *testing.T) {
	cfg := newTestCfg(t, "http://unused")
	os.WriteFile(cfg.DataFile, []byte("not json"), 0644)
	if err := parse(cfg); err == nil {
		t.Fatal("expected parse error")
	}
}
