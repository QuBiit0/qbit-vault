package tui_test

import (
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/tui"
)

func syncPane(b *fakeBackend) tui.Model { return pressAll(newModel(b, false), digit('5')) }

func TestSyncNotLinkedSaysSoAndNamesTheCommandsToLink(t *testing.T) {
	m := syncPane(newReady())
	wantView(t, m, "not linked", "does not sync", "qbit-vault remote register", "qbit-vault remote join")
}

func TestSyncLinkedShowsServerDeviceRoundAndConflicts(t *testing.T) {
	b := newReady()
	b.syncStatus = tui.SyncStatus{Linked: true, Server: "https://vault.tec5.tech", Device: "a1c9f0", LastRound: "2026-11-05T09:14:02Z", Conflicts: 1}
	m := syncPane(b)
	wantView(t, m, "linked", "https://vault.tec5.tech", "a1c9f0", "2026-11-05 09:14", "1 conflict",
		"qbit-vault remote conflicts", "qbit-vault remote resolve", "qbit-vault remote approve")
}

func TestSyncStatusStatesOfflinePendingAndNoRoundYet(t *testing.T) {
	b := newReady()
	b.syncStatus = tui.SyncStatus{Linked: true, Server: "https://s", Device: "d", Conflicts: 0, Offline: true, PendingPush: true}
	m := syncPane(b)
	wantView(t, m, "offline", "offline", "QBIT_VAULT_NO_REMOTE", "no round yet", "push pending", "no conflicts")
}

func TestSyncLockedVaultShowsTheCountsOfTheLastRound(t *testing.T) {
	b := newReady()
	b.syncStatus = tui.SyncStatus{Linked: true, Server: "https://s", Device: "d", LastRound: "2026-11-05T09:14:02Z", Conflicts: 2, Cached: true}
	m := syncPane(b)
	wantView(t, m, "cached counts", "2 conflicts", "from the last round")
	b.syncStatus.Conflicts = -1
	m = syncPane(b)
	wantView(t, m, "unknown counts", "conflicts unknown", "unlock")
}

func TestSyncNeverShowsPairingOrRecoveryMaterialAndHasNoActionKeys(t *testing.T) {
	b := newReady()
	b.syncStatus = tui.SyncStatus{Linked: true, Server: "https://s", Device: "d", Conflicts: 0}
	m := syncPane(b)
	wantView(t, m, "sync", "native dialog", "never here")
	for _, c := range []rune{'p', 'c', 'r', 'k', 'l', 'a', 's', 'x', 'v'} {
		m = pressAll(m, runeKey(c))
	}
	if suspended != 0 || len(b.repaired)+len(b.uninstalled)+len(b.registered) != 0 {
		t.Error("a key in the Sync section did something")
	}
}
