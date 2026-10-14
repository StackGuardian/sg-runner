//go:build unix

package wrapper

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// run runs a shell script under Run with its own termination log.
func run(t *testing.T, script string, args ...string) (code int, termLog string, stderr string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "termination-log")
	errPath := filepath.Join(dir, "stderr")
	errFile, err := os.Create(errPath)
	if err != nil {
		t.Fatal(err)
	}
	defer errFile.Close()
	code = Run(append([]string{"sh", "-c", script}, args...), Options{Stderr: errFile, TerminationLog: logPath})
	b, _ := os.ReadFile(logPath)
	e, _ := os.ReadFile(errPath)
	return code, string(b), string(e)
}

func TestExitCodes(t *testing.T) {
	for _, c := range []struct {
		script  string
		code    int
		message string
	}{
		{"exit 0", 0, ""},
		{"exit 1", 1, ""},
		{"exit 10", 10, ""},
		{"exit 11", 0, "sg-exit-code=11"},
		{"exit 12", 0, "sg-exit-code=12"},
		{"exit 13", 13, ""},
		{"exit 137", 137, ""},
		{"kill -TERM $$", 128 + 15, ""},
		{"kill -KILL $$", 128 + 9, ""},
	} {
		code, msg, _ := run(t, c.script)
		if code != c.code || msg != c.message {
			t.Errorf("%q: exit %d, message %q; want %d, %q", c.script, code, msg, c.code, c.message)
		}
	}
}

func TestUnwritableTerminationLogStillExitsZero(t *testing.T) {
	code := Run([]string{"sh", "-c", "exit 11"}, Options{TerminationLog: "/nonexistent/dir/termination-log"})
	if code != 0 {
		t.Errorf("exit %d", code)
	}
}

func TestArgsAndPathLookup(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	// "sh" is found through PATH, the args pass as they are.
	code, _, _ := run(t, `printf '%s|' "$@" > "$0"`, out, "a b", "$HOME", "")
	b, _ := os.ReadFile(out)
	if code != 0 || string(b) != "a b|$HOME||" {
		t.Errorf("exit %d, args %q", code, b)
	}
}

func TestCommandNotFound(t *testing.T) {
	dir := t.TempDir()
	errFile, _ := os.Create(filepath.Join(dir, "stderr"))
	defer errFile.Close()
	if code := Run([]string{"sg-no-such-command"}, Options{Stderr: errFile}); code != 127 {
		t.Errorf("not found: exit %d", code)
	}
	noExec := filepath.Join(dir, "script")
	_ = os.WriteFile(noExec, []byte("#!/bin/sh\n"), 0o644)
	if code := Run([]string{noExec}, Options{Stderr: errFile}); code != 126 {
		t.Errorf("not executable: exit %d", code)
	}
	if code := Run(nil, Options{Stderr: errFile}); code != 2 {
		t.Errorf("no command: exit %d", code)
	}
}

// TestForwardsSignals sends each signal to this process (as the kubelet would
// to the wrapper) and checks the child got it.
func TestForwardsSignals(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{
		"TERM": syscall.SIGTERM, "INT": syscall.SIGINT, "HUP": syscall.SIGHUP,
		"QUIT": syscall.SIGQUIT, "USR1": syscall.SIGUSR1, "USR2": syscall.SIGUSR2,
	} {
		dir := t.TempDir()
		ready, got := filepath.Join(dir, "ready"), filepath.Join(dir, "got")
		script := `trap 'echo ` + name + ` > "$1"; exit 12' ` + name + `; touch "$0"; while :; do sleep 0.01; done`
		done := make(chan struct{})
		var code int
		var msg string
		go func() { code, msg, _ = run(t, script, ready, got); close(done) }()
		waitFile(t, ready)
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: the child never ended", name)
		}
		b, _ := os.ReadFile(got)
		if strings.TrimSpace(string(b)) != name || code != 0 || msg != "sg-exit-code=12" {
			t.Errorf("%s: child got %q, exit %d, message %q", name, b, code, msg)
		}
	}
}

// TestReapsZombies: an exited child that isn't the step's (as PID 1 inherits
// orphans) is reaped along the way.
func TestReapsZombies(t *testing.T) {
	// This process's own child, never waited for: a zombie once it exits.
	var attr os.ProcAttr
	p, err := os.StartProcess("/bin/sh", []string{"sh", "-c", "exit 3"}, &attr)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if code, _, _ := run(t, "sleep 0.1; exit 4"); code != 4 {
		t.Errorf("exit %d", code)
	}
	// Reaped already: nothing left to wait for.
	var ws syscall.WaitStatus
	if pid, err := syscall.Wait4(p.Pid, &ws, syscall.WNOHANG, nil); err == nil || pid != -1 {
		t.Errorf("the zombie is still there: pid %d, err %v", pid, err)
	}
}

func TestInstall(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "sg-step-wrapper")
	if err := Install(dest); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dest)
	self, _ := os.Executable()
	sfi, _ := os.Stat(self)
	if err != nil || fi.Mode().Perm() != 0o755 || fi.Size() != sfi.Size() {
		t.Errorf("installed %v %v (want 0755, %d bytes)", fi.Mode(), err, sfi.Size())
	}
	entries, _ := os.ReadDir(filepath.Dir(dest))
	if len(entries) != 1 {
		t.Errorf("left temp files: %v", entries)
	}
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", path)
		}
	}
}
