//go:build !windows

package runner

import (
	"os/exec"
	"syscall"
)

// tree is the child's process group.
type tree struct{ pgid int }

// prepare puts the child in its own process group.
func prepare(cmd *exec.Cmd, _ string, _ []string) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func attach(cmd *exec.Cmd) (*tree, error) { return &tree{pgid: cmd.Process.Pid}, nil }

// kill ends every process of the group.
func (t *tree) kill() { _ = syscall.Kill(-t.pgid, syscall.SIGKILL) }

// release sweeps descendants that outlived the child: none may keep running
// with the injected environment once the run is over.
func (t *tree) release() { t.kill() }
