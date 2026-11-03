//go:build !windows

package prompt

import "os/exec"

func detach(*exec.Cmd) {}

// interactiveSession is only a question on Windows.
func interactiveSession() bool { return true }
