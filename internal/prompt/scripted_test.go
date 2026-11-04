//go:build e2eprompt

package prompt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func scriptedEnv(t *testing.T, answers string) (Env, string) {
	t.Helper()
	consumed = 0
	dir := t.TempDir()
	vars := map[string]string{
		EnvBackend:            "scripted",
		EnvScriptedAnswers:    filepath.Join(dir, "answers"),
		EnvScriptedTranscript: filepath.Join(dir, "transcript"),
		EnvScriptedPassphrase: filepath.Join(dir, "pass"),
		EnvScriptedWait:       "300ms",
	}
	if err := os.WriteFile(vars[EnvScriptedAnswers], []byte(answers), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vars[EnvScriptedPassphrase], []byte("TESTSECRET_pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Env{GOOS: "linux", Getenv: func(k string) string { return vars[k] }}, vars[EnvScriptedTranscript]
}

func TestScriptedBackendAnswersInOrderAndWritesTranscript(t *testing.T) {
	env, transcript := scriptedEnv(t, "TESTSECRET_value\ny\n2\n")
	b, err := SelectWith(env)
	if err != nil {
		t.Fatal(err)
	}
	if b.Name() != "scripted" {
		t.Fatalf("name = %q", b.Name())
	}
	s, err := b.Secret(SecretRequest{Name: "invite code", Reason: "Register"})
	if err != nil || string(s.Reveal()) != "TESTSECRET_value" {
		t.Fatalf("secret: %v", err)
	}
	if ok, err := b.Confirm("Sync?"); err != nil || !ok {
		t.Fatalf("confirm = %v, %v", ok, err)
	}
	if i, err := b.Choose("scope", []string{"a", "b", "c"}, 0); err != nil || i != 1 {
		t.Fatalf("choose = %d, %v", i, err)
	}
	p, err := b.Passphrase(true)
	if err != nil || string(p.Reveal()) != "TESTSECRET_pass" {
		t.Fatalf("passphrase: %v", err)
	}
	sh, ok := b.(Shower)
	if !ok {
		t.Fatal("scripted backend is not a Shower")
	}
	if err := sh.Show("Recovery key", "AAAA-BBBB\nline two"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(transcript)
	got := string(raw)
	for _, want := range []string{"ASK secret name=\"invite code\"", "ASK confirm", "ASK choose", "ASK passphrase confirm=true", "SHOW Recovery key", "| AAAA-BBBB", "| line two"} {
		if !strings.Contains(got, want) {
			t.Errorf("transcript lacks %q:\n%s", want, got)
		}
	}
	for _, leak := range []string{"TESTSECRET_value", "TESTSECRET_pass"} {
		if strings.Contains(got, leak) {
			t.Errorf("transcript holds an answer: %s", leak)
		}
	}
}

func TestScriptedBackendWaitsForALateAnswerThenGivesUp(t *testing.T) {
	env, _ := scriptedEnv(t, "")
	path := env.Getenv(EnvScriptedAnswers)
	b, err := SelectWith(env)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = os.WriteFile(path, []byte("late\n"), 0o600)
	}()
	s, err := b.Secret(SecretRequest{Name: "x"})
	if err != nil || string(s.Reveal()) != "late" {
		t.Fatalf("late answer: %v", err)
	}
	if _, err := b.Secret(SecretRequest{Name: "y"}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("exhausted script = %v, want ErrCancelled", err)
	}
}

func TestScriptedBackendNeedsItsFiles(t *testing.T) {
	b, err := SelectWith(Env{Getenv: func(k string) string {
		if k == EnvBackend {
			return "scripted"
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Secret(SecretRequest{Name: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}
