package mullvadproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"testing"
	"time"
)

func makeRelays() *MullvadRelays {
	return &MullvadRelays{
		Wireguard: WireguardEndpoints{
			Ipv4Gateway: "10.64.0.1",
			Ipv6Gateway: "fc00:bbbb:bbbb:bb01::1",
			PortRanges:  [][]int{{51820, 51820}},
			Relays: []Relay{
				{Active: true, IncludeInCountry: true, Hostname: "se-got-wg-001", Location: "se-got", Weight: 100, AdditionalProperties: map[string]any{"owned": true}},
				{Active: true, IncludeInCountry: true, Hostname: "de-fra-wg-002", Location: "de-fra", Weight: 50, AdditionalProperties: map[string]any{"owned": false}},
				{Active: false, IncludeInCountry: true, Hostname: "us-nyc-wg-003", Location: "us-nyc", Weight: 75, AdditionalProperties: map[string]any{"owned": true}},
				{Active: true, IncludeInCountry: false, Hostname: "fr-par-wg-004", Location: "fr-par", Weight: 25, AdditionalProperties: map[string]any{"owned": true}},
				{Active: true, IncludeInCountry: true, Hostname: "se-sto-wg-005", Location: "se-sto", Weight: 200, AdditionalProperties: map[string]any{"owned": true}},
			},
		},
	}
}

// Guards the nil-guard in SelectProxies so callers get a clear error instead of
// a nil-pointer panic when invoked before the relay list is loaded.
func TestSelectProxies_NoRelaysLoaded(t *testing.T) {
	Relays.Store(nil)
	_, err := SelectProxies(DefaultMullvadConfig(), 0, RelayFilter{})
	if err == nil {
		t.Fatal("expected error when relay list not loaded")
	}
}

// Verifies Active=false and IncludeInCountry=false relays are filtered out.
// These flags are Mullvad's signal that a relay is unhealthy or geo-misclassified,
// so leaking them as proxies would route traffic through broken endpoints.
func TestSelectProxies_SkipsInactiveAndExcluded(t *testing.T) {
	Relays.Store(makeRelays())
	t.Cleanup(func() { Relays.Store(nil) })

	got, err := SelectProxies(DefaultMullvadConfig(), 0, RelayFilter{})
	if err != nil {
		t.Fatal(err)
	}
	// 3 active + include_in_country: se-got, de-fra, se-sto
	if len(got) != 3 {
		t.Fatalf("want 3 relays, got %d: %v", len(got), got)
	}
	for _, p := range got {
		if p == "socks5://us-nyc-wg-socks5-003.relays.mullvad.net:1080" ||
			p == "socks5://fr-par-wg-socks5-004.relays.mullvad.net:1080" {
			t.Errorf("inactive/excluded relay leaked: %s", p)
		}
	}
}

// Locks the `-wg-` → `-wg-socks5-` hostname rewrite and ProxyPort injection.
// Mullvad exposes SOCKS5 on a sibling host, so any regression here produces
// proxy URLs that connect to the wireguard endpoint instead and silently fail.
func TestSelectProxies_HostnameRewriteAndPort(t *testing.T) {
	Relays.Store(makeRelays())
	t.Cleanup(func() { Relays.Store(nil) })

	cfg := DefaultMullvadConfig()
	cfg.ProxyPort = 443
	got, err := SelectProxies(cfg, 1, RelayFilter{Location: regexp.MustCompile("^se-got$")})
	if err != nil {
		t.Fatal(err)
	}
	want := "socks5://se-got-wg-socks5-001.relays.mullvad.net:443"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("want [%s], got %v", want, got)
	}
}

// Confirms the Location regex is applied per-relay. Callers depend on this
// to pin traffic to a country/city, so a broken match would silently route
// through wrong jurisdictions.
func TestSelectProxies_LocationFilter(t *testing.T) {
	Relays.Store(makeRelays())
	t.Cleanup(func() { Relays.Store(nil) })

	got, _ := SelectProxies(DefaultMullvadConfig(), 0, RelayFilter{Location: regexp.MustCompile("^se-")})
	if len(got) != 2 {
		t.Fatalf("want 2 se-* relays, got %d: %v", len(got), got)
	}
}

// Exercises both Owned=true and Owned=false branches. `owned` lives in
// AdditionalProperties (map[string]any type-assert path), so this catches
// regressions in the nested lookup as well as the boolean match.
func TestSelectProxies_OwnedFilter(t *testing.T) {
	Relays.Store(makeRelays())
	t.Cleanup(func() { Relays.Store(nil) })

	yes := true
	owned, _ := SelectProxies(DefaultMullvadConfig(), 0, RelayFilter{Owned: &yes})
	if len(owned) != 2 { // se-got, se-sto
		t.Fatalf("want 2 owned relays, got %d: %v", len(owned), owned)
	}
	no := false
	notOwned, _ := SelectProxies(DefaultMullvadConfig(), 0, RelayFilter{Owned: &no})
	if len(notOwned) != 1 || notOwned[0] != "socks5://de-fra-wg-socks5-002.relays.mullvad.net:1080" {
		t.Fatalf("want 1 non-owned de-fra relay, got %v", notOwned)
	}
}

// Ensures the Weight predicate is invoked and used to exclude relays.
// Callers use this to bias toward high-capacity relays; a no-op filter
// would spread load to low-weight hosts.
func TestSelectProxies_WeightFilter(t *testing.T) {
	Relays.Store(makeRelays())
	t.Cleanup(func() { Relays.Store(nil) })

	got, _ := SelectProxies(DefaultMullvadConfig(), 0, RelayFilter{Weight: func(w int) bool { return w >= 100 }})
	if len(got) != 2 { // se-got=100, se-sto=200
		t.Fatalf("want 2 relays with weight >= 100, got %d: %v", len(got), got)
	}
}

// Verifies the early-exit on limit. Off-by-one here would either return
// limit+1 results or loop over every relay unnecessarily on large lists.
func TestSelectProxies_Limit(t *testing.T) {
	Relays.Store(makeRelays())
	t.Cleanup(func() { Relays.Store(nil) })

	got, _ := SelectProxies(DefaultMullvadConfig(), 2, RelayFilter{})
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
}

// Points AmIConnectedURL at an httptest server to exercise the real IsConnected
// code path end-to-end: HTTP GET, status check, body read, JSON decode, boolean
// return. Covers the happy path where Mullvad reports the client is connected.
func TestIsConnected_True(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"mullvad_exit_ip": true, "ip": "1.2.3.4"})
	}))
	defer srv.Close()

	orig := AmIConnectedURL
	AmIConnectedURL = srv.URL
	t.Cleanup(func() { AmIConnectedURL = orig })

	ok, err := IsConnected(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected IsConnected=true")
	}
}

// Covers the mullvad_exit_ip=false branch — a real user not routed through
// Mullvad — so a regression that flips the boolean or misreads the field is
// caught.
func TestIsConnected_False(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"mullvad_exit_ip": false})
	}))
	defer srv.Close()

	orig := AmIConnectedURL
	AmIConnectedURL = srv.URL
	t.Cleanup(func() { AmIConnectedURL = orig })

	ok, err := IsConnected(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected IsConnected=false")
	}
}

// Transport failure (unreachable host) must surface as an error. Silently
// returning false would be indistinguishable from "connected via a non-Mullvad
// exit" and lead callers to wrong conclusions during outages.
func TestIsConnected_TransportError(t *testing.T) {
	orig := AmIConnectedURL
	AmIConnectedURL = "http://127.0.0.1:1"
	t.Cleanup(func() { AmIConnectedURL = orig })

	if _, err := IsConnected(t.Context()); err == nil {
		t.Fatal("expected transport error")
	}
}

// Malformed body (non-JSON or JSON missing required field) must propagate
// the decode error rather than defaulting to a false "not connected" result.
func TestIsConnected_MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	orig := AmIConnectedURL
	AmIConnectedURL = srv.URL
	t.Cleanup(func() { AmIConnectedURL = orig })

	if _, err := IsConnected(t.Context()); err == nil {
		t.Fatal("expected decode error")
	}
}

// Non-2xx responses must surface as errors so callers don't mistake an API
// outage (503, captive portal) for "not connected to Mullvad".
func TestIsConnected_ErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	orig := AmIConnectedURL
	AmIConnectedURL = srv.URL
	t.Cleanup(func() { AmIConnectedURL = orig })

	if _, err := IsConnected(t.Context()); err == nil {
		t.Fatal("expected error on 503")
	}
}

// StartUpdater must run an initial update, then continue firing on its
// ticker until ctx is canceled, and close the errors channel on exit.
// Uses a short interval so the second update fires inside the test timeout.
func TestStartUpdater_RunsAndTicksAndCloses(t *testing.T) {
	Relays.Store(nil)
	t.Cleanup(func() { Relays.Store(nil) })

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(relayJSON))
		}
		hits.Add(1)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := MullvadConfig{
		RelayURL:       srv.URL,
		DataFile:       filepath.Join(dir, "relays.json"),
		MetaFile:       filepath.Join(dir, "relays.meta.json"),
		ProxyPort:      1080,
		UpdateInterval: 20 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(t.Context())
	errs := StartUpdater(ctx, cfg)

	// Wait until ticker has fired at least once past the initial update.
	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() < 3 {
		t.Fatalf("expected >=3 server hits (1 initial GET + subsequent HEADs), got %d", hits.Load())
	}

	cancel()
	// Channel must close after ctx done.
	select {
	case _, ok := <-errs:
		if ok {
			// drain remaining errors until closed
			for range errs {
			}
		}
	case <-time.After(time.Second):
		t.Fatal("errs channel not closed after ctx cancel")
	}
}

// StartUpdater must reject a non-positive UpdateInterval up front rather than
// panicking from time.NewTicker. The error is surfaced on the channel and the
// channel is closed without starting the update loop.
func TestStartUpdater_RejectsNonPositiveInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			cfg := DefaultMullvadConfig()
			cfg.UpdateInterval = interval

			errs := StartUpdater(t.Context(), cfg)

			var got error
			select {
			case got = <-errs:
			case <-time.After(time.Second):
				t.Fatal("expected an error, got none")
			}
			if got == nil {
				t.Fatal("expected non-nil error")
			}

			// Channel must be closed (no update loop started).
			select {
			case _, ok := <-errs:
				if ok {
					t.Fatal("channel should be closed after rejecting config")
				}
			case <-time.After(time.Second):
				t.Fatal("channel not closed")
			}
		})
	}
}

// StartUpdater must surface update errors on the returned channel. A HEAD
// that returns 500 is the simplest way to force an error on the initial tick.
func TestStartUpdater_SurfacesErrorOnChannel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := MullvadConfig{
		RelayURL:       srv.URL,
		DataFile:       filepath.Join(dir, "relays.json"),
		MetaFile:       filepath.Join(dir, "relays.meta.json"),
		ProxyPort:      1080,
		UpdateInterval: time.Hour,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	errs := StartUpdater(ctx, cfg)

	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("expected non-nil error from initial update")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no error surfaced")
	}
}

// Generated UnmarshalJSON enforces `mullvad_exit_ip` is present. This pins
// that behavior so a regenerated schema that drops the required check is
// caught — without it we'd treat malformed responses as "not connected".
func TestAmIConnected_MissingRequiredField(t *testing.T) {
	var res AmIConnected
	err := json.Unmarshal([]byte(`{"ip":"1.2.3.4"}`), &res)
	if err == nil {
		t.Fatal("expected error for missing mullvad_exit_ip")
	}
}
