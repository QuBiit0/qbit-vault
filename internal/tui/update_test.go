package tui_test

import (
	"reflect"
	"strings"
	"testing"
)

func TestUpdateIsAStaticPlannedScreenWithTheManualWayToUpdate(t *testing.T) {
	m := pressAll(newModel(newReady(), false), digit('7'))
	wantView(t, m, "update", "Re-run the install command to upgrade",
		"go install github.com/QuBiit0/qbit-vault/cmd/qbit-vault@latest", "No network call")
	for _, gone := range []string{"planned", "phase 5", "not available yet"} {
		if strings.Contains(strings.ToLower(m.View()), gone) {
			t.Errorf("the Update screen still says %q", gone)
		}
	}
}

func TestUpdateSectionDoesNothingWhateverIsPressed(t *testing.T) {
	b := newReady()
	m := pressAll(newModel(b, false), digit('7'))
	before := *b
	m = pressAll(m, runeKey('u'), runeKey('r'), runeKey('s'), runeKey('x'), runeKey('a'), runeKey('v'), keyEnter)
	if !reflect.DeepEqual(b.repaired, before.repaired) || b.doctorCalls != before.doctorCalls || suspended != 0 || b.verifyCalls != 0 {
		t.Error("a key in the Update section did something")
	}
	wantView(t, m, "update", "Re-run the install command to upgrade")
}
