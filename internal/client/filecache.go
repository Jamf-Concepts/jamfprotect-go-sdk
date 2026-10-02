// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// maxCachedTokenLifetime bounds how far in the future a cached expiry may lie.
// Jamf Protect issues tokens valid for 24 hours, so any later expiry (beyond a
// small allowance for clock skew) was not written by this SDK and is ignored.
const maxCachedTokenLifetime = 24*time.Hour + 5*time.Minute

// maxCacheEntryBytes bounds how much of a cache file Load reads.
const maxCacheEntryBytes = 64 << 10

// FileTokenCache persists tokens to disk as JSON files. The directory must be
// private to the running user: entries are only read from, and written to, a
// directory owned by the current user that group and others cannot write.
type FileTokenCache struct {
	dir string
}

// NewFileTokenCache creates a FileTokenCache that stores tokens in the given directory.
func NewFileTokenCache(dir string) *FileTokenCache {
	return &FileTokenCache{dir: dir}
}

type fileCacheEntry struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Load reads a cached token from disk. Entries that are not regular files owned
// by the current user, are accessible by group or others, live in a directory
// that is not private, or carry an implausible expiry are treated as a miss.
func (c *FileTokenCache) Load(key string) (string, time.Time, bool) {
	root, err := openPrivateDir(c.dir)
	if err != nil {
		return "", time.Time{}, false
	}
	defer func() { _ = root.Close() }()

	f, err := root.OpenFile(cacheFileName(key), os.O_RDONLY|noFollowFlags, 0)
	if err != nil {
		return "", time.Time{}, false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || checkPrivateFile(info) != nil {
		return "", time.Time{}, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCacheEntryBytes))
	if err != nil {
		return "", time.Time{}, false
	}
	var entry fileCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return "", time.Time{}, false
	}
	if entry.ExpiresAt.After(time.Now().Add(maxCachedTokenLifetime)) {
		return "", time.Time{}, false
	}
	return entry.AccessToken, entry.ExpiresAt, true
}

// Store writes a token to disk. The token is written to a freshly created 0600
// temporary file and renamed into place, so an existing file or symlink at the
// cache path is replaced rather than written through.
func (c *FileTokenCache) Store(key string, token string, expiresAt time.Time) error {
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return fmt.Errorf("creating token cache directory: %w", err)
	}
	root, err := openPrivateDir(c.dir)
	if err != nil {
		return fmt.Errorf("token cache directory is not private: %w", err)
	}
	defer func() { _ = root.Close() }()

	data, err := json.Marshal(fileCacheEntry{AccessToken: token, ExpiresAt: expiresAt})
	if err != nil {
		return fmt.Errorf("marshalling cached token: %w", err)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("creating cached token file: %w", err)
	}
	tmp := fmt.Sprintf(".jamfprotect-token-%x.tmp", suffix)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("creating cached token file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = root.Remove(tmp)
		return fmt.Errorf("writing cached token: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("writing cached token: %w", err)
	}
	if err := root.Rename(tmp, cacheFileName(key)); err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("writing cached token: %w", err)
	}
	return nil
}

// openPrivateDir opens dir as an os.Root and verifies, on the opened handle,
// that it is private to the current user. Operating through the handle keeps
// later file operations inside the directory that was checked, even if the
// path is renamed or replaced in the meantime.
func openPrivateDir(dir string) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err == nil {
		err = checkPrivateDir(info)
	}
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return root, nil
}

// CacheKey computes a deterministic cache key from a base URL and client ID.
func CacheKey(baseURL, clientID string) string {
	h := sha256.Sum256([]byte(baseURL + "\x00" + clientID))
	return fmt.Sprintf("%x", h)
}

func (c *FileTokenCache) path(key string) string {
	return filepath.Join(c.dir, cacheFileName(key))
}

func cacheFileName(key string) string {
	return "jamfprotect-token-" + key
}
