//go:build unix

// sg-step-wrapper is the init process of a step container (see
// internal/wrapper):
//
//	sg-step-wrapper -- <command> [args...]   run the step's command
//	sg-step-wrapper install <dest>           copy itself to dest (an init container)
//
// It writes nothing to stdout: that's the step's.
package main

import (
	"fmt"
	"os"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/wrapper"
)

func main() {
	args := os.Args[1:]
	switch {
	case len(args) >= 2 && args[0] == "--":
		os.Exit(wrapper.Run(args[1:], wrapper.Options{}))
	case len(args) == 2 && args[0] == "install":
		if err := wrapper.Install(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "sg-step-wrapper: install: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: sg-step-wrapper -- <command> [args...] | sg-step-wrapper install <dest>")
		os.Exit(2)
	}
}
