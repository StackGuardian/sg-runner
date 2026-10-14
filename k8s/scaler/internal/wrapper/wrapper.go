//go:build unix

// Package wrapper is sg-step-wrapper: the init process of a step container.
// It runs the step's command as its child, forwards signals to it, reaps
// zombies, and exits 0 for the exit codes StackGuardian gives meaning to (11:
// approval required, 12: finished early), leaving the code in the
// container's termination message, so the pod ends Completed rather than
// Failed. See k8s/docs/steps-api.md.
package wrapper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// TerminationLog is where the kubelet reads a container's termination message.
const TerminationLog = "/dev/termination-log"

// ExitCodePrefix starts the termination message of a mapped exit code.
const ExitCodePrefix = "sg-exit-code="

// Mapped are the exit codes reported in the termination message and turned
// into exit 0.
var Mapped = map[int]bool{11: true, 12: true}

// forwarded are the signals passed on to the child.
var forwarded = []os.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2}

// Install copies the running executable to dest, executable by anyone.
func Install(dest string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	in, err := os.Open(self)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".sg-step-wrapper-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}

// Options are a run's stdio and termination log (the process's own and
// TerminationLog when unset).
type Options struct {
	Stdin, Stdout, Stderr *os.File
	TerminationLog        string
}

// Run runs argv (argv[0] looked up in PATH) as a child until it exits and
// returns the exit code to exit with.
func Run(argv []string, o Options) int {
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.TerminationLog == "" {
		o.TerminationLog = TerminationLog
	}
	fail := func(code int, err error) int {
		fmt.Fprintf(o.Stderr, "sg-step-wrapper: %v\n", err)
		return code
	}
	if len(argv) == 0 {
		return fail(2, errors.New("no command"))
	}

	// Before the child starts, so neither a signal nor its exit is missed.
	sigs := make(chan os.Signal, 32)
	signal.Notify(sigs, append([]os.Signal{syscall.SIGCHLD}, forwarded...)...)
	defer signal.Stop(sigs)

	path, err := exec.LookPath(argv[0])
	if err != nil {
		// As shells do: 126 for a file that can't run, 127 for none.
		if errors.Is(err, os.ErrPermission) {
			return fail(126, err)
		}
		return fail(127, err)
	}
	// os.File stdio: the child gets the descriptors themselves, nothing is
	// copied, and only reap() below waits for it.
	cmd := &exec.Cmd{Path: path, Args: argv, Stdin: o.Stdin, Stdout: o.Stdout, Stderr: o.Stderr}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fail(126, err)
		}
		return fail(127, err)
	}
	child := cmd.Process.Pid

	// Signals can coalesce or, past the channel's buffer, drop: reap now and
	// then anyway.
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		if ws, done := reap(child); done {
			return exitCode(ws, o.TerminationLog)
		}
		select {
		case sig := <-sigs:
			if sig != syscall.SIGCHLD {
				_ = cmd.Process.Signal(sig)
			}
		case <-tick.C:
		}
	}
}

// reap waits for every exited child without blocking (as PID 1, orphans are
// ours too) and reports the main child's status once it exited.
func reap(child int) (syscall.WaitStatus, bool) {
	var status syscall.WaitStatus
	done := false
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if pid <= 0 || err != nil {
			return status, done
		}
		if pid == child {
			status, done = ws, true
		}
	}
}

// exitCode is the code to exit with for the child's status; a mapped code
// goes to the termination log and becomes 0.
func exitCode(ws syscall.WaitStatus, terminationLog string) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	code := ws.ExitStatus()
	if Mapped[code] {
		// Best effort: without the message the step still ends; only its code
		// is lost.
		_ = os.WriteFile(terminationLog, []byte(ExitCodePrefix+strconv.Itoa(code)), 0o644)
		return 0
	}
	return code
}
