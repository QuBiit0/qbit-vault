package runner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The test binary doubles as the child process: when GV_RUNNER_HELPER is set,
// TestMain runs that mode instead of the tests. This keeps the tests portable
// (no sh, cat or sleep needed).
const (
	envHelper = "GV_RUNNER_HELPER"
	envArg    = "GV_RUNNER_ARG"
)

func helperMain(mode string) {
	arg := os.Getenv(envArg)
	switch mode {
	case "env": // print NAME=<value|<unset>> for each name in arg
		for _, n := range strings.Split(arg, ",") {
			v, ok := os.LookupEnv(n)
			if !ok {
				v = "<unset>"
			}
			fmt.Printf("%s=%s\n", n, v)
		}
	case "encodings": // the value of env var arg, in every modeled encoding
		v := os.Getenv(arg)
		j, _ := json.Marshal(v)
		fmt.Println(v)
		fmt.Println(base64.StdEncoding.EncodeToString([]byte(v)))
		fmt.Println(base64.URLEncoding.EncodeToString([]byte(v)))
		fmt.Println(url.QueryEscape(v))
		fmt.Println(string(j[1 : len(j)-1]))
		fmt.Fprintln(os.Stderr, v)
	case "split": // the value in two writes with a pause in between
		v := os.Getenv(arg)
		h := len(v) / 2
		os.Stdout.WriteString("pre " + v[:h])
		time.Sleep(150 * time.Millisecond)
		os.Stdout.WriteString(v[h:] + " post\n")
	case "exit":
		n, _ := strconv.Atoi(arg)
		os.Exit(n)
	case "selfkill":
		selfKill()
	case "sleep":
		time.Sleep(time.Minute)
	case "partial-sleep":
		os.Stdout.WriteString("PARTIAL_OUT\n")
		os.Stderr.WriteString("PARTIAL_ERR\n")
		time.Sleep(time.Minute)
	case "tree": // start a grandchild that outlives us unless the tree is killed
		c := exec.Command(os.Args[0])
		c.Env = append(os.Environ(), envHelper+"=sleep")
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if err := c.Start(); err != nil {
			os.Exit(90)
		}
		_ = os.WriteFile(arg, []byte(strconv.Itoa(c.Process.Pid)), 0o600)
		os.Stdout.WriteString("started\n")
		time.Sleep(time.Minute)
	case "chunks": // arg bytes of filler followed by TAILMARK
		n, _ := strconv.Atoi(arg)
		line := strings.Repeat("x", 99) + "\n"
		for written := 0; written < n; written += len(line) {
			os.Stdout.WriteString(line)
		}
		os.Stdout.WriteString("TAILMARK\n")
	case "cat":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "argv": // write argv to the file named by arg
		_ = os.WriteFile(arg, []byte(strings.Join(os.Args, "\x00")), 0o600)
	case "pwd":
		wd, _ := os.Getwd()
		fmt.Println(wd)
	}
	os.Exit(0)
}
