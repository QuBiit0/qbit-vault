package pi_test

import (
	"os"
	"testing"
)

// The Pi adapter reads PI_CODING_AGENT_DIR from the real environment by
// default, and Pi sets it for the processes it starts: a test that forgot
// WithGetenv would reach the developer's real Pi config. Clear it for the
// whole binary.
func TestMain(m *testing.M) {
	_ = os.Unsetenv("PI_CODING_AGENT_DIR")
	os.Exit(m.Run())
}

func TestAgentDirOverrideIsCleared(t *testing.T) {
	if v, ok := os.LookupEnv("PI_CODING_AGENT_DIR"); ok {
		t.Fatalf("PI_CODING_AGENT_DIR is set to %q in the test process", v)
	}
}
