//go:build !unix

package analyzer

import "os/exec"

// arrangeGroupKill falls back to the default direct-process kill on platforms
// without process groups.
func arrangeGroupKill(command *exec.Cmd) {}
