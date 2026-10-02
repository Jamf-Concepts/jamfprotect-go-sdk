// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

//go:build !unix

package client

import (
	"errors"
	"io/fs"
)

// noFollowFlags is empty on platforms without O_NOFOLLOW.
const noFollowFlags = 0

// checkPrivateDir reports an error unless info describes a directory.
// Ownership and mode bits are not checked on platforms without Unix permissions.
func checkPrivateDir(info fs.FileInfo) error {
	if !info.IsDir() {
		return errors.New("not a directory")
	}
	return nil
}

// checkPrivateFile is a no-op on platforms without Unix permissions.
func checkPrivateFile(fs.FileInfo) error {
	return nil
}
