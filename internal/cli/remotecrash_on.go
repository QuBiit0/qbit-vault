//go:build crashseam

package cli

// rotateCrash is a test seam, compiled only with -tags crashseam: it is called
// at named points of a rotation and a non-nil result stops the command there,
// as a crash would. A release build does not contain it
// (remotecrash_release_test.go).
var rotateCrash func(step string) error

func crashAt(step string) error {
	if rotateCrash != nil {
		return rotateCrash(step)
	}
	return nil
}
