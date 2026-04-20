// Copyright © 2026 fakeapate <fakeapate@pm.me>
// SPDX-License-Identifier: MIT

// Package mullvadproxy provides a client for the Mullvad VPN relay list API and
// helpers for selecting SOCKS5 proxies backed by Mullvad WireGuard relays.
//
// Typical use: call [StartUpdater] once at program start to keep [Relays]
// fresh, then call [SelectProxies] with a [RelayFilter] to build a list of
// proxy URLs. [IsConnected] queries am.i.mullvad.net to verify the current
// egress IP belongs to Mullvad.

//go:generate go-jsonschema -p mullvadproxy -o relay.go mullvad_relay_schema.json
//go:generate go-jsonschema -p mullvadproxy -o ami.go mullvad_ami_schema.json

package mullvadproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AmIConnectedURL is the endpoint queried by [IsConnected].
// Exposed as a variable so tests can point it at an httptest server.
var AmIConnectedURL = "https://am.i.mullvad.net/json"

// StartUpdater runs an initial relay list update, then refreshes on
// cfg.UpdateInterval until ctx is canceled. Errors from every update
// attempt (initial and scheduled) are sent on the returned channel;
// the channel is closed when ctx is done. Consumers that do not want
// errors can drain or ignore the channel — the buffer is small, so
// persistent backpressure drops errors rather than blocking updates.
//
// The caller must set cfg.UpdateInterval to a positive duration; if it
// is zero or negative, StartUpdater surfaces an error on the channel
// and closes it without starting the update loop. Use
// [DefaultMullvadConfig] for a working baseline.
func StartUpdater(ctx context.Context, cfg MullvadConfig) <-chan error {
	errs := make(chan error, 1)
	if cfg.UpdateInterval <= 0 {
		errs <- fmt.Errorf("mullvadproxy: UpdateInterval must be positive, got %s", cfg.UpdateInterval)
		close(errs)
		return errs
	}
	go func() {
		defer close(errs)
		send := func(err error) {
			if err == nil {
				return
			}
			select {
			case errs <- err:
			default:
			}
		}
		send(update(ctx, cfg))
		ticker := time.NewTicker(cfg.UpdateInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				send(update(ctx, cfg))
			}
		}
	}()
	return errs
}

// IsConnected queries [AmIConnectedURL] and reports whether the current
// egress IP is a Mullvad exit. It returns an error if the request fails,
// the response status is non-2xx, or the body cannot be decoded.
func IsConnected(ctx context.Context) (connected bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, AmIConnectedURL, nil)
	if err != nil {
		return false, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("am.i.mullvad.net: status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var res AmIConnected
	if err := json.Unmarshal(data, &res); err != nil {
		return false, err
	}

	return res.MullvadExitIp, nil
}

// RelayFilter specifies which relays [SelectProxies] should include.
// Zero values impose no constraint for that field.
// Active and IncludeInCountry are always required to be true and are not exposed.
type RelayFilter struct {
	Location *regexp.Regexp // match relay.Location against pattern; nil = any
	Owned    *bool          // nil = any, true = owned only, false = non-owned only
	Weight   func(int) bool // nil = no weight filter
}

// SelectProxies returns up to limit proxy strings for relays matching filter,
// formatted as socks5://hostname:<port> for use with colly's proxy switcher.
// limit <= 0 means no limit. Reports an error if the relay list is not loaded.
func SelectProxies(cfg MullvadConfig, limit int, filter RelayFilter) ([]string, error) {
	snapshot := Relays.Load()
	if snapshot == nil {
		return nil, errors.New("relay list not loaded")
	}

	port := strconv.Itoa(cfg.ProxyPort)
	var results []string
	for _, relay := range snapshot.Wireguard.Relays {
		if !relay.Active || !relay.IncludeInCountry {
			continue
		}
		if filter.Location != nil && !filter.Location.MatchString(relay.Location) {
			continue
		}
		if filter.Owned != nil {
			if props, ok := relay.AdditionalProperties.(map[string]any); ok {
				if owned, ok := props["owned"].(bool); ok && owned != *filter.Owned {
					continue
				}
			}
		}
		if filter.Weight != nil && !filter.Weight(relay.Weight) {
			continue
		}
		hostname := strings.ReplaceAll(relay.Hostname, "-wg-", "-wg-socks5-")
		results = append(results, "socks5://"+hostname+".relays.mullvad.net:"+port)
		if limit > 0 && len(results) == limit {
			break
		}
	}

	return results, nil
}
