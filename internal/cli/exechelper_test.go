package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as the child process of `exec` tests: when
// GV_CLI_CHILD is set, TestMain runs that mode instead of the tests, which
// keeps them portable (no sh utilities needed).
const (
	envChild     = "GV_CLI_CHILD"
	envChildArg  = "GV_CLI_ARG"
	envChildExit = "GV_CLI_EXIT"
)

func childMain(mode string) {
	arg := os.Getenv(envChildArg)
	code, _ := strconv.Atoi(os.Getenv(envChildExit))
	switch mode {
	case "mark": // proves the command ran
		_ = os.WriteFile(arg, []byte("ran"), 0o600)
	case "leaks": // the value of env var arg in every encoding the redactor models
		v := os.Getenv(arg)
		j, _ := json.Marshal(v)
		fmt.Println("raw:" + v)
		fmt.Println("b64:" + base64.StdEncoding.EncodeToString([]byte(v)))
		fmt.Println("b64u:" + base64.URLEncoding.EncodeToString([]byte(v)))
		fmt.Println("pct:" + url.QueryEscape(v))
		fmt.Println("json:" + string(j[1:len(j)-1]))
		fmt.Fprintln(os.Stderr, "err:"+v)
		h := len(v) / 2
		os.Stdout.WriteString("split:" + v[:h])
		time.Sleep(120 * time.Millisecond)
		os.Stdout.WriteString(v[h:] + "\n")
		fmt.Println("done")
	case "env": // NAME=<value tail or <unset>> for each name in arg
		for _, n := range strings.Split(arg, ",") {
			v, ok := os.LookupEnv(n)
			switch {
			case !ok:
				v = "<unset>"
			case len(v) > 7:
				v = "..." + v[len(v)-7:]
			}
			fmt.Printf("%s=%s\n", n, v)
		}
	case "args":
		fmt.Println(strings.Join(os.Args[1:], ","))
	case "partial-sleep":
		os.Stdout.WriteString("PARTIAL_OUT\n")
		time.Sleep(time.Minute)
	case "sabotage-audit": // arg is the vault home: replace the audit log by a directory
		_ = os.Remove(filepath.Join(arg, "audit.jsonl"))
		_ = os.Mkdir(filepath.Join(arg, "audit.jsonl"), 0o700)
	case "cat":
		buf := make([]byte, 64)
		n, _ := os.Stdin.Read(buf)
		os.Stdout.Write(buf[:n])
	}
	os.Exit(code)
}

// child selects the child's mode for the next exec and returns the command
// that starts it: the quoted path of the test binary.
func child(t *testing.T, mode, arg string, exit int) string {
	t.Helper()
	t.Setenv(envChild, mode)
	t.Setenv(envChildArg, arg)
	t.Setenv(envChildExit, strconv.Itoa(exit))
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return `"` + filepath.ToSlash(exe) + `"`
}
