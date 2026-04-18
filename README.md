# mullvadproxy

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

