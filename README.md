# mullvadproxy

[![CI](https://github.com/fakeapate/mullvadproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/fakeapate/mullvadproxy/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/FakeApate/mullvadproxy/graph/badge.svg?token=JXVG9RMPER)](https://codecov.io/github/FakeApate/mullvadproxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/fakeapate/mullvadproxy)](https://goreportcard.com/report/github.com/fakeapate/mullvadproxy)
[![Go Reference](https://pkg.go.dev/badge/github.com/fakeapate/mullvadproxy.svg)](https://pkg.go.dev/github.com/fakeapate/mullvadproxy)
[![License](https://img.shields.io/github/license/fakeapate/mullvadproxy)](LICENSE)

Package mullvadproxy provides a client for the Mullvad VPN relay list API and helpers for selecting SOCKS5 proxies backed by Mullvad WireGuard relays.

## Example

```Go
maxWeight := 99
proxyCount := 10

cfg := mullvadproxy.DefaultMullvadConfig()
connected, err := mullvadproxy.IsConnected()

if err != nil || !connected {
    panic(err)
}

weightFilter := func(num int) bool { return num <= maxWeight }
relayFilter := mullvadproxy.RelayFilter{Weight: weightFilter}

proxies, err := mullvadproxy.SelectProxies(cfg, proxyCount, relayFilter)

mullvadproxy.StartUpdater(cfg)
```

## Development

Just don't forget to run `go generate` before testing.

