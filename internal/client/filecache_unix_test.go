// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

//go:build unix

package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestFileTokenCache_Store_RejectsGroupWritableDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	cache := NewFileTokenCache(dir)

	if err := cache.Store("key1", "secret-token", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("expected Store to fail for a group/other-writable directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files written, found %d", len(entries))
	}
}

func TestFileTokenCache_Store_ReplacesSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	dir := filepath.Join(root, "cache")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "elsewhere")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	cache := NewFileTokenCache(dir)
	if err := os.Symlink(target, cache.path("key1")); err != nil {
		t.Fatal(err)
	}

	if err := cache.Store("key1", "secret-token", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("symlink target was written through: %q", got)
	}
	info, err := os.Lstat(cache.path("key1"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("expected regular 0600 file, got %v", info.Mode())
	}
}

func TestFileTokenCache_Store_ReplacesPreexistingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache := NewFileTokenCache(dir)
	path := cache.path("key1")
	if err := os.WriteFile(path, []byte("{}"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := cache.Store("key1", "secret-token", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("expected the pre-existing file to be replaced, not written in place")
	}
	if after.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %o", after.Mode().Perm())
	}
}

func TestFileTokenCache_Store_LeavesNoTempFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache := NewFileTokenCache(dir)
	if err := cache.Store("key1", "tok", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one cache file, found %d", len(entries))
	}
}

func TestFileTokenCache_Store_AcceptsReadableDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := NewFileTokenCache(dir)

	if err := cache.Store("key1", "tok", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Store failed for a 0755 directory: %v", err)
	}
	if _, _, ok := cache.Load("key1"); !ok {
		t.Fatal("expected Load to succeed for a 0755 directory")
	}
}

func TestFileTokenCache_Load_Rejects(t *testing.T) {
	t.Parallel()

	valid := func(t *testing.T) []byte {
		t.Helper()
		data, err := json.Marshal(fileCacheEntry{AccessToken: "planted", ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	tests := []struct {
		name  string
		setup func(t *testing.T, dir, path string)
	}{
		{
			name: "group-readable file",
			setup: func(t *testing.T, _, path string) {
				if err := os.WriteFile(path, valid(t), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, dir, path string) {
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, valid(t), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "group-writable directory",
			setup: func(t *testing.T, dir, path string) {
				if err := os.WriteFile(path, valid(t), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o777); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "fifo",
			setup: func(t *testing.T, _, path string) {
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "far-future expiry",
			setup: func(t *testing.T, _, path string) {
				data := []byte(`{"access_token":"planted","expires_at":"2999-01-01T00:00:00Z"}`)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			cache := NewFileTokenCache(dir)
			tt.setup(t, dir, cache.path("key1"))

			if tok, _, ok := cache.Load("key1"); ok {
				t.Fatalf("expected Load to reject entry, got token %q", tok)
			}
		})
	}
}

func TestFileTokenCache_Load_AllowsClockSkew(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache := NewFileTokenCache(dir)
	expiresAt := time.Now().Add(24*time.Hour + 2*time.Minute)
	if err := cache.Store("key1", "tok", expiresAt); err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	if _, _, ok := cache.Load("key1"); !ok {
		t.Fatal("expected an expiry within the clock-skew allowance to be accepted")
	}
}
