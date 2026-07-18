//go:build unix

package analyzer

import (
	"os/exec"
	"syscall"
)

// arrangeGroupKill runs the provider in its own process group and kills the
// whole group when the context ends, so scanners spawned by the provider
// cannot outlive the analyzer deadline.
func arrangeGroupKill(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return err
		}
		return nil
	}
}
