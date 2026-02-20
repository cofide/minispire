//go:build linux

package spiredevserver

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func getCallerInfo(conn *net.UnixConn) (CallerInfo, error) {
	sys, err := conn.SyscallConn()
	if err != nil {
		return CallerInfo{}, err
	}

	var info CallerInfo
	var sysErr error

	sys.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			sysErr = err
			return
		}
		info.PID = int32(cred.Pid)
		info.UID = uint32(cred.Uid)
		info.GID = uint32(cred.Gid)
	})

	if sysErr != nil {
		return CallerInfo{}, sysErr
	}

	// Linux specific: Read from /proc
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", info.PID))
	if err == nil {
		_, info.BinaryName = filepath.Split(path)
	}

	return info, nil
}
