// Copyright © 2026 fakeapate <fakeapate@pm.me>
// SPDX-License-Identifier: MIT

package mullvadproxy

import "time"

// MullvadConfig holds all Mullvad VPN configuration.
type MullvadConfig struct {
	RelayURL       string        `toml:"relay_url"`       // Mullvad wireguard relay list API endpoint
	DataFile       string        `toml:"data_file"`       // path to the cached relay list on disk
	MetaFile       string        `toml:"meta_file"`       // path to the cached relay list metadata on disk
	ProxyPort      int           `toml:"proxy_port"`      // SOCKS5 port on Mullvad relay hosts
	UpdateInterval time.Duration `toml:"update_interval"` // how often to refresh the relay list
}

// DefaultMullvadConfig returns a [MullvadConfig] with sensible defaults.
func DefaultMullvadConfig() MullvadConfig {
	return MullvadConfig{
		RelayURL:       "https://api.mullvad.net/public/relays/wireguard/v2",
		DataFile:       "relays.json",
		MetaFile:       "relays.meta.json",
		ProxyPort:      1080,
		UpdateInterval: time.Hour,
	}
}
