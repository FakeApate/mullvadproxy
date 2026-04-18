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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Relays holds the most recently loaded Mullvad relay list.
// It is nil until the first successful parse completes.
var Relays *MullvadRelays

// AmIConnectedURL is the endpoint queried by [IsConnected].
// Exposed as a variable so tests can point it at an httptest server.
var AmIConnectedURL = "https://am.i.mullvad.net/json"

// StartUpdater performs an initial relay list update and then checks for updates
// at the interval specified by cfg.UpdateInterval.
// It returns immediately after the first update; subsequent checks run in the background.
func StartUpdater(cfg MullvadConfig) {
	if err := update(cfg); err != nil {
		log.Printf("mullvad: initial update failed: %v", err)
	}
	go func() {
		ticker := time.NewTicker(cfg.UpdateInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := update(cfg); err != nil {
				log.Printf("mullvad: update failed: %v", err)
			}
		}
	}()
}

// IsConnected queries [AmIConnectedURL] and reports whether the current
// egress IP is a Mullvad exit. It returns an error if the request fails,
// the response status is non-2xx, or the body cannot be decoded.
func IsConnected() (bool, error) {
	resp, err := http.Get(AmIConnectedURL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
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
	if Relays == nil {
		return nil, errors.New("relay list not loaded")
	}

	port := strconv.Itoa(cfg.ProxyPort)
	var results []string
	for _, relay := range Relays.Wireguard.Relays {
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
