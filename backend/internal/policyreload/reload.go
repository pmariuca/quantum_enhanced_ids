// Package policyreload signals the daemon to reload its policy files.
package policyreload

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Signal reads the daemon PID from pidFile and sends SIGUSR1 to it.
func Signal(pidFile string) error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("read pid file %s: %w", pidFile, err)
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("parse pid %q: %w", pidStr, err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	if err := proc.Signal(syscall.SIGUSR1); err != nil {
		return fmt.Errorf("signal process %d: %w", pid, err)
	}
	return nil
}

// DaemonAlive returns true if the PID in pidFile belongs to a running process.
func DaemonAlive(pidFile string) bool {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 checks existence without actually sending a signal.
	return proc.Signal(syscall.Signal(0)) == nil
}
