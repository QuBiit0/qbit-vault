//go:build !windows

package prompt

import "os/exec"

func detach(*exec.Cmd) {}

// systemRoot is only a question on Windows.
func systemRoot() string { return "" }

// interactiveSession is only a question on Windows.
func interactiveSession() bool { return true }
