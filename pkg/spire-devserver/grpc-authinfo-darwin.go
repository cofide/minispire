//go:build darwin

package spiredevserver

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func getCallerInfo(conn *net.UnixConn) (CallerInfo, error) {
	sys, err := conn.SyscallConn()
	if err != nil {
		return CallerInfo{}, err
	}

	var info CallerInfo
	var sysErr error

	sys.Control(func(fd uintptr) {
		pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if err != nil {
			sysErr = fmt.Errorf("failed to get peer PID: %w", err)
			return
		}
		info.PID = int32(pid)

		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			sysErr = fmt.Errorf("failed to get peer creds: %w", err)
			return
		}
		info.UID = cred.Uid
		// Xucred contains groups, usually the first one is the primary GID
		if len(cred.Groups) > 0 {
			info.GID = cred.Groups[0]
		}
	})

	if sysErr != nil {
		return CallerInfo{}, sysErr
	}

	// Note: Getting the BinaryName on macOS is complex.
	// It requires using CGO to call `proc_pidpath` from libproc,
	// or calling the external `ps` command (which is slow).
	// /proc does not exist on macOS.
	info.BinaryName = "unknown-darwin"

	return info, nil
}
