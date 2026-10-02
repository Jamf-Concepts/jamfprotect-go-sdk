// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

//go:build unix

package client

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// noFollowFlags makes Load refuse a symlink at the cache path and keeps it from
// blocking if a FIFO has been put there.
const noFollowFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// checkPrivateDir reports an error unless info describes a directory owned by
// the current user that group and others cannot write.
func checkPrivateDir(info fs.FileInfo) error {
	if !info.IsDir() {
		return errors.New("not a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("writable by group or others (mode %o)", info.Mode().Perm())
	}
	return checkOwner(info)
}

// checkPrivateFile reports an error unless the file is owned by the current
// user and grants no permissions to group or others.
func checkPrivateFile(info fs.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible by group or others (mode %o)", info.Name(), info.Mode().Perm())
	}
	return checkOwner(info)
}

// checkOwner reports an error unless the file is owned by the effective user.
func checkOwner(info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine file owner")
	}
	if uid := os.Geteuid(); int(st.Uid) != uid {
		return fmt.Errorf("owned by uid %d, not the current user (uid %d)", st.Uid, uid)
	}
	return nil
}
