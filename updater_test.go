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
func newServer(t *testing.T, etag, lastMod string) (*httptest.Server, *int, *int) {
	t.Helper()
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
			if _, err := w.Write([]byte(relayJSON)); err != nil {
				t.Errorf("test server write: %v", err)
			}
		}
	}))
	return srv, &headCount, &getCount
}

// Cold-start path: no in-memory Relays, no disk cache → must GET and parse.
// This is the first-ever-run scenario; a regression would leave Relays nil
// and every SelectProxies call failing.
func TestUpdate_FetchesWhenNoCache(t *testing.T) {
	Relays.Store(nil)
	srv, _, getCount := newServer(t, `"v1"`, time.Now().UTC().Format(time.RFC1123))
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)

	if err := update(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if *getCount != 1 {
		t.Fatalf("want 1 GET, got %d", *getCount)
	}
	if r := Relays.Load(); r == nil || len(r.Wireguard.Relays) != 1 {
		t.Fatal("relays not parsed")
	}
	if _, err := os.Stat(cfg.DataFile); err != nil {
		t.Fatal("data file not written")
	}
	Relays.Store(nil)
}

// Regression test for the bug fixed earlier: when Relays==nil but the disk
// cache is valid and the remote ETag matches, update must parse from disk
// instead of refetching. Counts GETs to prove no network fetch happens.
func TestUpdate_UsesDiskCacheWhenETagMatches(t *testing.T) {
	Relays.Store(nil)
	etag := `"v1"`
	srv, _, getCount := newServer(t, etag, "")
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)

	// Seed disk cache + meta with matching etag.
	if err := os.WriteFile(cfg.DataFile, []byte(relayJSON), 0644); err != nil {
		t.Fatal(err)
	}
	metaBytes, err := json.Marshal(metadata{ETag: etag})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.MetaFile, metaBytes, 0644); err != nil {
		t.Fatal(err)
	}

	if err := update(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if *getCount != 0 {
		t.Fatalf("want 0 GET (cache hit), got %d", *getCount)
	}
	if Relays.Load() == nil {
		t.Fatal("expected relays parsed from disk cache")
	}
	Relays.Store(nil)
}

// Steady-state tick: Relays already in memory, remote unchanged → no-op.
// Protects against wasted bandwidth and unnecessary disk writes on the
// hourly ticker when nothing has changed.
func TestUpdate_SkipsWhenRelaysLoadedAndETagMatches(t *testing.T) {
	Relays.Store(makeRelays())
	etag := `"v2"`
	srv, _, getCount := newServer(t, etag, "")
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)
	metaBytes, err := json.Marshal(metadata{ETag: etag})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.MetaFile, metaBytes, 0644); err != nil {
		t.Fatal(err)
	}

	if err := update(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if *getCount != 0 {
		t.Fatalf("want 0 GET, got %d", *getCount)
	}
	Relays.Store(nil)
}

// ETag mismatch must trigger a refetch even when Relays is already loaded.
// Without this, the client would serve stale relay data indefinitely after
// Mullvad publishes a new list.
func TestUpdate_FetchesWhenETagChanged(t *testing.T) {
	Relays.Store(makeRelays())
	srv, _, getCount := newServer(t, `"new"`, "")
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)
	metaBytes, err := json.Marshal(metadata{ETag: `"old"`})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.MetaFile, metaBytes, 0644); err != nil {
		t.Fatal(err)
	}

	if err := update(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if *getCount != 1 {
		t.Fatalf("want 1 GET, got %d", *getCount)
	}
	Relays.Store(nil)
}

// Non-2xx HEAD must surface as an error so StartUpdater can log it.
// Previously a 500 would pass the nil-err check and feed junk headers into
// the freshness comparison, potentially overwriting the cache with garbage.
func TestUpdate_ReturnsErrorOnHTTPFailure(t *testing.T) {
	Relays.Store(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)

	if err := update(t.Context(), cfg); err == nil {
		t.Fatal("expected error on 500")
	}
}

// loadMeta must degrade gracefully to a zero metadata{} when the file is
// absent — that's the signal update uses to force a first fetch. Returning
// an error instead would break the cold-start path.
func TestLoadMeta_MissingFileReturnsZero(t *testing.T) {
	cfg := newTestCfg(t, "http://unused")
	m, err := loadMeta(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.ETag != "" || !m.LastModified.IsZero() {
		t.Fatalf("want zero metadata, got %+v", m)
	}
}

// Corrupt meta file must surface as an error rather than being silently
// treated as zero — the library leaves that decision to the caller.
func TestLoadMeta_CorruptFileReturnsError(t *testing.T) {
	cfg := newTestCfg(t, "http://unused")
	if err := os.WriteFile(cfg.MetaFile, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMeta(cfg); err == nil {
		t.Fatal("expected error on corrupt meta")
	}
}

// Corrupt meta must propagate from loadMeta through update. Without this,
// update would silently act on zero metadata and spuriously refetch (or
// worse, hide disk corruption from the caller).
func TestUpdate_ReturnsErrorOnCorruptMeta(t *testing.T) {
	Relays.Store(nil)
	srv, _, _ := newServer(t, `"v1"`, "")
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)
	if err := os.WriteFile(cfg.MetaFile, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := update(t.Context(), cfg); err == nil {
		t.Fatal("expected error on corrupt meta")
	}
}

// Cold start with a corrupt on-disk cache must fall back to a network
// fetch rather than propagating the parse error. This is the recovery path
// for partial writes / disk corruption.
func TestUpdate_RefetchesWhenDiskCacheCorrupt(t *testing.T) {
	Relays.Store(nil)
	t.Cleanup(func() { Relays.Store(nil) })
	// HEAD returns no ETag/Last-Modified so remoteIsNewer is false → exercise
	// the cold-start "try disk, else fetch" branch.
	srv, _, getCount := newServer(t, "", "")
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)
	if err := os.WriteFile(cfg.DataFile, []byte("garbage"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := update(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if *getCount != 1 {
		t.Fatalf("want 1 GET fallback, got %d", *getCount)
	}
	if Relays.Load() == nil {
		t.Fatal("relays not parsed after refetch")
	}
}

// HEAD returns 2xx but GET returns 5xx — the new status guard in fetch must
// reject the body rather than writing a 500 error page to DataFile and then
// failing to parse it.
func TestFetch_RejectsNon2xxGET(t *testing.T) {
	Relays.Store(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)

	if err := update(t.Context(), cfg); err == nil {
		t.Fatal("expected error on GET 500")
	}
	if _, err := os.Stat(cfg.DataFile); err == nil {
		t.Fatal("DataFile must not be written when GET fails")
	}
}

// fetch must surface disk write errors. Pointing DataFile at a path whose
// parent directory does not exist is the simplest way to force WriteFile
// to fail without relying on permissions.
func TestFetch_SurfacesDataFileWriteError(t *testing.T) {
	Relays.Store(nil)
	srv, _, _ := newServer(t, `"v1"`, "")
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)
	cfg.DataFile = filepath.Join(cfg.DataFile, "does", "not", "exist", "relays.json")

	if err := update(t.Context(), cfg); err == nil {
		t.Fatal("expected DataFile write error")
	}
}

// Same for the meta file: a failure to persist meta must be surfaced so
// callers know the freshness check for the next tick is unreliable.
func TestFetch_SurfacesMetaFileWriteError(t *testing.T) {
	Relays.Store(nil)
	srv, _, _ := newServer(t, `"v1"`, "")
	defer srv.Close()
	cfg := newTestCfg(t, srv.URL)
	cfg.MetaFile = filepath.Join(cfg.MetaFile, "does", "not", "exist", "meta.json")

	if err := update(t.Context(), cfg); err == nil {
		t.Fatal("expected MetaFile write error")
	}
}

// HEAD transport failure (server closed before request) must surface so the
// updater caller can log it. Covers the httpClient.Do error branch in update.
func TestUpdate_ReturnsErrorOnHEADTransportFailure(t *testing.T) {
	Relays.Store(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // immediately
	cfg := newTestCfg(t, srv.URL)

	if err := update(t.Context(), cfg); err == nil {
		t.Fatal("expected transport error")
	}
}

// parse must propagate JSON errors so update can fall back to a network
// fetch when the on-disk cache is corrupted (partial write, disk full, etc.)
// rather than silently leaving Relays nil.
func TestParse_InvalidJSONReturnsError(t *testing.T) {
	cfg := newTestCfg(t, "http://unused")
	if err := os.WriteFile(cfg.DataFile, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := parse(cfg); err == nil {
		t.Fatal("expected parse error")
	}
}
