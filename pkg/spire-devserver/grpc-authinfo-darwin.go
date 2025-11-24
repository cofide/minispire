//go:build darwin

package spiredevserver

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/shirou/gopsutil/v3/process"
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
		if len(cred.Groups) > 0 {
			info.GID = cred.Groups[0]
		}
	})

	if sysErr != nil {
		return CallerInfo{}, sysErr
	}

	info.BinaryName = resolveBinaryName(info.PID)

	return info, nil
}

func resolveBinaryName(pid int32) string {
	proc, err := process.NewProcess(pid)
	if err != nil {
		// Process likely exited between socket read and lookup
		return "unknown-exited"
	}

	exePath, err := proc.Exe()
	if err != nil {
		// Permission denied or zombie process
		return "unknown-denied"
	}

	// Strip path for clean SPIFFE ID
	return filepath.Base(exePath)
}
