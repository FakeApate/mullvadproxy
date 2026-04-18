// Copyright © 2026 fakeapate <fakeapate@pm.me>
// SPDX-License-Identifier: MIT

package mullvadproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// Relays holds the most recently loaded Mullvad relay list.
// Readers call Relays.Load(); a nil return means no list is loaded yet.
// Writes happen only from update (single-writer, many-reader).
var Relays atomic.Pointer[MullvadRelays]

// httpClient is the shared client used for all outbound Mullvad API calls.
// Timeout covers the full request; per-call cancellation is via context.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// metadata stores the ETag and Last-Modified values from the last successful fetch,
// persisted to disk so freshness checks survive restarts.
type metadata struct {
	ETag         string    `json:"etag"`
	LastModified time.Time `json:"last_modified"`
}

// update refreshes [Relays] from the Mullvad API. It issues a conditional
// HEAD first and only re-downloads the full list when the remote ETag or
// Last-Modified indicates newer content. On cold start (Relays == nil) it
// prefers the on-disk cache and only falls back to a network fetch if that
// cache is missing or corrupt.
func update(ctx context.Context, cfg MullvadConfig) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, cfg.RelayURL, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HEAD %s: status %d", cfg.RelayURL, resp.StatusCode)
	}

	remoteETag := resp.Header.Get("ETag")
	remoteLastModified, _ := time.Parse(time.RFC1123, resp.Header.Get("Last-Modified"))

	meta, err := loadMeta(cfg)
	if err != nil {
		return err
	}

	remoteIsNewer := (remoteETag != "" && remoteETag != meta.ETag) ||
		(!remoteLastModified.IsZero() && remoteLastModified.After(meta.LastModified))

	if remoteIsNewer {
		if err := fetch(ctx, cfg, remoteETag, remoteLastModified); err != nil {
			return err
		}
		return parse(cfg)
	}

	if Relays.Load() == nil {
		if err := parse(cfg); err == nil {
			return nil
		}
		if err := fetch(ctx, cfg, remoteETag, remoteLastModified); err != nil {
			return err
		}
		return parse(cfg)
	}

	return nil
}

// fetch downloads the relay list, writes it to cfg.DataFile, and records the
// supplied etag and lastModified to cfg.MetaFile so the next update call can
// short-circuit when the remote has not changed.
func fetch(ctx context.Context, cfg MullvadConfig, etag string, lastModified time.Time) (err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.RelayURL, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: status %d", cfg.RelayURL, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := os.WriteFile(cfg.DataFile, data, 0644); err != nil {
		return err
	}

	metaData, err := json.Marshal(metadata{ETag: etag, LastModified: lastModified})
	if err != nil {
		return err
	}
	return os.WriteFile(cfg.MetaFile, metaData, 0644)
}

// parse reads cfg.DataFile and populates the package-level [Relays] variable.
// Returns an error if the file is missing or contains invalid JSON; callers
// use that signal to fall back to a network refetch.
func parse(cfg MullvadConfig) error {
	data, err := os.ReadFile(cfg.DataFile)
	if err != nil {
		return err
	}
	var relays MullvadRelays
	if err := json.Unmarshal(data, &relays); err != nil {
		return err
	}
	Relays.Store(&relays)
	return nil
}

// loadMeta returns the persisted freshness metadata from cfg.MetaFile.
// A missing file yields a zero metadata and nil error (expected on cold
// start). Read or unmarshal failures are returned to the caller — the
// library does not decide whether corrupt metadata should be ignored.
func loadMeta(cfg MullvadConfig) (metadata, error) {
	data, err := os.ReadFile(cfg.MetaFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return metadata{}, nil
		}
		return metadata{}, err
	}
	var meta metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return metadata{}, err
	}
	return meta, nil
}
