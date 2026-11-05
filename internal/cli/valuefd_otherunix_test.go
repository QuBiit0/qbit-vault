//go:build !windows && !linux && !darwin

package cli

import "testing"

func pollerFD(*testing.T) (int, bool) { return 0, false }
