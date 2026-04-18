package mullvadproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
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
